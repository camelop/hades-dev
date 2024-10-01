import os
import time
import pandas as pd

TMPFS_MOUNT_LOC = "./tmp"
def mount_tmpfs(loc=TMPFS_MOUNT_LOC, size="32G"):
    os.makedirs(loc, exist_ok=True)
    command = f"sudo mount -o size={size} -t tmpfs none {loc}"
    print("[Run->]", command)

    # os.system(command)
    print("[[ Skipped as non-root ]]")

    tmpfs_mount_loc = loc
    # speed test
    command = f"dd if=/dev/zero of={loc}/test.tmp bs=1M count=1024 oflag=dsync"
    print("[Run->]", command)
    os.system(command)
    os.system(f"rm {loc}/test.tmp")

DEFAULT_LINEITEM_SIZE = 6001215
TPC_H_ROOT_FOLDER = "./tpc-h-v3.0.1"
def gen_lineitem(lineitem_size=None):
    if lineitem_size is None:
        lineitem_size = DEFAULT_LINEITEM_SIZE
        scaling_factor = 1.0
    else:
        scaling_factor = lineitem_size / DEFAULT_LINEITEM_SIZE + 0.1 # make sure there is enough records to clip from
    command = f"cd {TMPFS_MOUNT_LOC} && ../{TPC_H_ROOT_FOLDER}/dbgen/dbgen -b ../{TPC_H_ROOT_FOLDER}/dbgen/dists.dss -v -s {scaling_factor:.3f} -T L -f"
    print("[Run->]", command)
    os.system(command)
    # calculate the line number from lineitem.tbl
    with open(f"{TMPFS_MOUNT_LOC}/lineitem.tbl") as f:
        lines = f.readlines()
        generated_num = len(lines)
    print(f"* Scaling factor used: {scaling_factor:.3f} ; Generated lineitem num: {generated_num} ; Expected lineitem num: {lineitem_size}")
    # write the clipped lineitem.tbl
    with open(f"{TMPFS_MOUNT_LOC}/lineitem.tbl", "w") as f:
        f.writelines(lines[:lineitem_size])

LINEITEM_COLUMNS = [
    "L_ORDERKEY",
    "L_PARTKEY",
    "L_SUPPKEY",
    "L_LINENUMBER",
    "L_QUANTITY",
    "L_EXTENDEDPRICE",
    "L_DISCOUNT",
    "L_TAX",
    "L_RETURNFLAG",
    "L_LINESTATUS",
    "L_SHIPDATE",
    "L_COMMITDATE",
    "L_RECEIPTDATE",
    "L_SHIPINSTRUCT",
    "L_SHIPMODE",
    "L_COMMENT",
]
def read_lineitem_df():
    loc = f"{TMPFS_MOUNT_LOC}/lineitem.tbl"
    if not os.path.exists(loc):
        raise Exception(f"File not found: {loc}")
    print("reading file...")
    nw = time.time()
    df = pd.read_csv(loc, sep="|", names=LINEITEM_COLUMNS, index_col=False)
    # update the data types
    df["L_SHIPDATE"] = pd.to_datetime(df["L_SHIPDATE"], format="%Y-%m-%d")
    df["L_QUANTITY"] = df["L_QUANTITY"].astype(float)
    df["L_EXTENDEDPRICE"] = df["L_EXTENDEDPRICE"].astype(float)
    df["L_DISCOUNT"] = df["L_DISCOUNT"].astype(float)
    df["L_TAX"] = df["L_TAX"].astype(float)
    print("offline - file reading time (s):", time.time() - nw)
    return df


DEFAULT_ORDERS_SIZE = 6000000
def gen_lineitem_orders(lineitem_size=None):
    if lineitem_size is None:
        lineitem_size = DEFAULT_LINEITEM_SIZE
        scaling_factor = 1.0
    else:
        scaling_factor = lineitem_size / DEFAULT_LINEITEM_SIZE + 0.001 # make sure there is enough records to clip from
    command = f"cd {TMPFS_MOUNT_LOC} && ../{TPC_H_ROOT_FOLDER}/dbgen/dbgen -b ../{TPC_H_ROOT_FOLDER}/dbgen/dists.dss -v -s {scaling_factor:.3f} -T o -f"
    print("[Run->]", command)
    os.system(command)
    # calculate the line number from orders.tbl
    with open(f"{TMPFS_MOUNT_LOC}/orders.tbl") as f:
        order_lines = f.readlines()
        generated_num = len(order_lines)
    with open(f"{TMPFS_MOUNT_LOC}/lineitem.tbl") as f:
        lineitem_lines = f.readlines()
        generated_l_num = len(lineitem_lines)
    print(f"* Scaling factor used: {scaling_factor:.3f} ; Generated orders num: {generated_num} ; Generated lineitem num: {generated_l_num}")
    # write the clipped orders.tbl
    with open(f"{TMPFS_MOUNT_LOC}/orders.tbl", "w") as f:
        f.writelines(order_lines)  # cannot crop the table anymore, as two tables are generated together
    with open(f"{TMPFS_MOUNT_LOC}/lineitem.tbl", "w") as f:
        f.writelines(lineitem_lines)

ORDERS_COLUMNS = [
    "O_ORDERKEY",
    "O_CUSTKEY",
    "O_ORDERSTATUS",
    "O_TOTALPRICE",
    "O_ORDERDATE",
    "O_ORDERPRIORITY",
    "O_CLERK",
    "O_SHIPPRIORITY",
    "O_COMMENT",
]
def read_orders_df():
    loc = f"{TMPFS_MOUNT_LOC}/orders.tbl"
    if not os.path.exists(loc):
        raise Exception(f"File not found: {loc}")
    print("reading file...")
    nw = time.time()
    df = pd.read_csv(loc, sep="|", names=ORDERS_COLUMNS, index_col=False)
    # update the data types
    df["O_TOTALPRICE"] = df["O_TOTALPRICE"].astype(float)
    df["O_ORDERDATE"] = pd.to_datetime(df["O_ORDERDATE"], format="%Y-%m-%d")
    print("offline - file reading time (s):", time.time() - nw)
    return df