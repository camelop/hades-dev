q1_sql = """
    select 
        l_returnflag,
        l_linestatus,
        sum(l_quantity) as sum_qty,
        sum(l_extendedprice) as sum_base_price, 
        sum(l_extendedprice*(1-l_discount)) as sum_disc_price, 
        sum(l_extendedprice*(1-l_discount)*(1+l_tax)) as sum_charge, 
        avg(l_quantity) as avg_qty,  
        avg(l_extendedprice) as avg_price, 
        avg(l_discount) as avg_disc,  
        count(*) as count_order 
    from  
        lineitem 
    where  
        l_shipdate <= date '1998-12-01' - interval '[DELTA]' day (3) 
    group by  
        l_returnflag,  
        l_linestatus 
    order by  
        l_returnflag,  
        l_linestatus;
    /* DELTA is randomly selected within [60. 120].  */
"""

import os
import time
import fire
from tqdm import tqdm
from query import *
from myutil import *

q1 = Query(
    select=Select(
        sum_cols=[
            "l_quantity",
            "l_extendedprice",
            "disc_price",
            "charge"
        ],
        avg_cols=[
            "l_quantity",
            "l_extendedprice",
            "l_discount"
        ],
        output_cnt=True
    ),
    from_col="lineitem",
    where=Predicate(
        op="le",
        bit_width=16,
        col="shipdate_int",
        value=3166,  # "1998-09-02" - "1990-01-01"
        children=[]
    ),
    group_by_col=[
        "l_returnflag",
        "l_linestatus"
    ]
)

class Q1:

    def get_df(self):
        df = read_lineitem_df()
        # generate query related cols
        # add the columns
        df["L_DISC_PRICE"] = df["L_EXTENDEDPRICE"] * (1 - df["L_DISCOUNT"])
        df["L_CHARGE"] = df["L_EXTENDEDPRICE"] * (1 - df["L_DISCOUNT"]) * (1 + df["L_TAX"])
        # keep two decimal places
        df["L_DISC_PRICE"] = df["L_DISC_PRICE"].round(2)
        df["L_CHARGE"] = df["L_CHARGE"].round(2)
        return df

    def gen(self, lineitem_size=None, target_folder="./tmp/q1_pre", skip_gen_lineitem=False):
        if not skip_gen_lineitem:
            gen_lineitem(lineitem_size)  # "{TMPFS_MOUNT_LOC}/lineitem.tbl" is generated
        df = self.get_df()
        # write data files
        nw = time.time()
        os.makedirs(target_folder, exist_ok=True)
        group_names = []
        group_cnt = {}
        grouped = df.groupby(["L_RETURNFLAG", "L_LINESTATUS"])
        for name, group in tqdm(grouped):
            group_name = f"{name[0]}_{name[1]}"
            group_names.append(group_name)
            group_cnt[group_name] = len(group)
            for col in ["L_QUANTITY", "L_EXTENDEDPRICE", "L_DISC_PRICE", "L_CHARGE", "L_DISCOUNT", "L_ORDERKEY", "L_SHIPDATE"]:
                group[col] = group[col].astype(str)
                group[col].to_csv(f"{target_folder}/{group_name}_{col[2:]}.txt", index=False, header=False)
        # also provide a transformed shipdate
        for name, group in tqdm(grouped):
            # count the date from 1990-01-01
            group["L_SHIPDATE_INT"] = (pd.to_datetime(group["L_SHIPDATE"]) - pd.to_datetime("1990-01-01")).dt.days.astype(str)
            group["L_SHIPDATE_INT"].to_csv(f"{target_folder}/{name[0]}_{name[1]}_SHIPDATE_INT.txt", index=False, header=False)
        print("dump grouped result (s):", time.time() - nw)

        # write client query plans
        q1.write_plan(target_folder, group_cnt)
    
    def run(self, core_num=64, skip_cpp=False, build_folder="./build", target_folder="./tmp/q1_pre"):
        output_filename = "qx." + self.__class__.__name__ + ".out"
        if not skip_cpp:
            abs_path = os.path.abspath(target_folder)
            os.system(f"folder=`pwd` && cd {build_folder} && make -j && taskset -c 0-{core_num-1} ./qx {abs_path} {core_num} | tee $folder/{output_filename} && cd $folder")
        nw = time.time()
        with open(output_filename) as f:
            lines = [l.strip() for l in f.readlines() if l.startswith("@")]
            m = {}
            key_captures = {
                ":cnt:": "count_order",
                ":agg_l_quantity:": "sum_qty",
                ":agg_l_extendedprice:": "sum_base_price",
                ":agg_disc_price:": "sum_disc_price",
                ":agg_charge:": "sum_charge",
                ":agg_l_discount:": "sum_disc",
            }
            for line in lines:
                group = line.split("server:group_")[1][:3]
                v = line.strip().split()[-1]
                for key, col in key_captures.items():
                    if key in line:
                        if (group, col) not in m:
                            m[(group, col)] = 0 if key == ":cnt:" else 0.0
                        m[(group, col)] += int(v) if key == ":cnt:" else float(v)
            for g in ["A_F", "N_F", "N_O", "R_F"]:
                m[(g, "avg_qty")] = m[(g, "sum_qty")] / m[(g, "count_order")]
                m[(g, "avg_price")] = m[(g, "sum_base_price")] / m[(g, "count_order")]
                m[(g, "avg_disc")] = m[(g, "sum_disc")] / m[(g, "count_order")]
                m.pop((g, "sum_disc"))  # not required in the query
        print("Parsed result: ")
        cols = ["sum_qty", "avg_qty", "sum_base_price", "avg_price", "sum_disc_price", "sum_charge", "avg_disc", "count_order"]
        print("\t" + "\t".join([f"{c: >15}" for c in cols]))
        for g in ["A_F", "N_F", "N_O", "R_F"]:
            print(g, end="\t")
            for col in cols:
                print(f"{m[(g, col)]: >15.2f}" if col != "count_order" else f"{m[(g, col)]: >15}", end="\t")
            print()
        print("online - client - analyze_decrypt (s):", time.time() - nw)


if __name__ == "__main__":
    fire.Fire(Q1)
