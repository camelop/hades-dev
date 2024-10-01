from __future__ import annotations
from typing import List, Any, Dict
from pydantic import BaseModel
from myutil import *
import os

CIPHER_SLOT_NUM = 2**14
MAPPING_BIT_WIDTH = 8
DECIMAL_DIGITS = 42
AGG_DIGITS = 3
assert(DECIMAL_DIGITS % AGG_DIGITS == 0)

MAPPING_PER_CIPHER = CIPHER_SLOT_NUM // (1 << MAPPING_BIT_WIDTH)

FILENAME_CLIENT_MAPPINGS = "client.mappings.txt"
FILENAME_PREPARE_ROTS = "server.prepare_rots.csv"
FILENAME_READ_IND_TBL = "server.read_ind_tbl.csv"
FILENAME_EMAP = "server.emap.csv"
FILENAME_CALC_IND_TASK = "server.calc_ind.csv"
FILENAME_CALC_IND_OPS = "server.calc_ind_ops.txt"
FILENAME_AGG = "server.agg.csv"

TASK_PREFIX_PREPARE_ROTS = "rot"
TASK_PREFIX_READ_IND_TBL = "readi"
TASK_PREFIX_EMAP = "emap"
TASK_PREFIX_CALC_IND = "calc"
TASK_PREFIX_AGG = "agg"


class Select(BaseModel):
    # assume all selected columns are 42-bit numbers
    sum_cols: List[str]
    avg_cols: List[str]
    output_cnt: bool

    def get_agg_cols(self) -> List[str]:
        ret = []
        for col in self.sum_cols:
            ret.append(col)
        for col in self.avg_cols:
            if col not in ret:
                ret.append(col)
        return ret

class Predicate(BaseModel):
    op: str  # col <op> value
    bit_width: int
    col: str
    value: Any
    children: List[Predicate]

    def gen_mapping_cmp(op, v_bit_width, x):
        if op == "lt":
            assert(x >= 0)
            return Predicate.gen_mapping_cmp("le", v_bit_width, x - 1)
        assert(v_bit_width <= 64)
        R = 1 << MAPPING_BIT_WIDTH
        step = (v_bit_width + MAPPING_BIT_WIDTH - 1) // MAPPING_BIT_WIDTH
        ret = [0] * (R * (step if op == "eq" else step * 2 - 1))
        for i in range(R):
            for j in range(step):
                v = (x >> (j * MAPPING_BIT_WIDTH)) & (R - 1)
                if op == "ge":
                    if j == 0:
                        ret[j * 2 * R + i] = 1 if i >= v else 0
                    else:
                        ret[j * 2 * R - R + i] = 1 if i == v else 0
                        ret[j * 2 * R + i] = 1 if i > v else 0
                elif op == "le":
                    if j == 0:
                        ret[j * 2 * R + i] = 1 if i <= v else 0
                    else:
                        ret[j * 2 * R - R + i] = 1 if i == v else 0
                        ret[j * 2 * R + i] = 1 if i < v else 0
                elif op == "eq":
                    ret[j * R + i] = 1 if i == v else 0
        return ret

    def get_mappings(self) -> List[int]:
        R = 1 << MAPPING_BIT_WIDTH
        if self.op in ["eq", "le", "lt", "ge"]:
            return Predicate.gen_mapping_cmp(self.op, self.bit_width, self.value)
        elif self.op == "and":
            ret = []
            for c in self.children:
                ret += c.get_mappings()
            return ret
        else:
            raise NotImplementedError(f"Unsupported op: {self.op}")
    
    def prepare_rots(self):
        W = 1 << MAPPING_BIT_WIDTH
        if self.op in ["eq", "le", "lt", "ge", "gt"]:
            step = (self.bit_width + MAPPING_BIT_WIDTH - 1) // MAPPING_BIT_WIDTH
            return [(0, i * W, W) for i in range(step if self.op == "eq" else step * 2 - 1)]
        elif self.op == "and":
            offset = 0
            ret = []
            for c in self.children:
                end_at = offset
                for ic, io, iw in c.prepare_rots():
                    ret.append((ic, offset + io, iw))
                    end_at = offset + io + iw
                    assert(offset + io <= CIPHER_SLOT_NUM)  # FIXME: update ic later
                offset = end_at
            return ret
        else:
            raise NotImplementedError(f"Unsupported op: {self.op}")
    
    def get_ind_cols(self):
        if self.op in ["eq", "le", "lt", "ge", "gt"]:
            return [self.col]
        elif self.op == "and":
            ret = []
            for c in self.children:
                ret += c.get_ind_cols()
            return list(set(ret))
        else:
            raise NotImplementedError(f"Unsupported op: {self.op}")
    
    def get_emap_ops(self):
        W = 1 << MAPPING_BIT_WIDTH
        if self.op in ["le", "lt", "ge", "gt"]:
            step = (self.bit_width + MAPPING_BIT_WIDTH - 1) // MAPPING_BIT_WIDTH
            return [(0, i * W, self.col, (i + 1) // 2 * MAPPING_BIT_WIDTH) for i in range(step * 2 - 1)]
        elif self.op == "and":
            ret = []
            offset = 0
            for c in self.children:
                end_at = offset
                for ic, io, col, starting_bit in c.get_emap_ops():
                    ret.append((ic, io + offset, col, starting_bit))
                    end_at = offset + io + W
                    assert(offset + io <= CIPHER_SLOT_NUM)
                offset = end_at
            return ret
        else:
            raise NotImplementedError(f"Unsupported op: {self.op}")

    def calc_ind_ops(self):
        W = 1 << MAPPING_BIT_WIDTH
        if self.op in ["le", "ge", "lt", "gt"] and self.bit_width == 16:
            var_in = 3
            var_all = 5
            mapped = [(0, 0 * W), (0, 1 * W), (0, 2 * W)]  # cipher-id, offset
            assert(len(mapped) == var_in)
            ops = [('mul', 0, 1, 3),        # c0c1
                   ('mul', 2, 3, 4),        # c0c1c2
                   ('neg_inplace', 4, -1, -1),      # -c0c1c2
                   ('add_inplace', 4, 2, -1),   # c2-c0c1c2
                   ('add_inplace', 4, 3, -1),   # c2+c0c1-c0c1c2
                ]
            return var_in, var_all, mapped, ops
        elif self.op == "and" and len(self.children) == 2:
            cl, cr = self.children
            var_in_l, var_all_l, mapped_l, ops_l = cl.calc_ind_ops()
            var_in_r, var_all_r, mapped_r, ops_r = cr.calc_ind_ops()
            var_in = var_in_l + var_in_r
            var_all = var_all_l + var_all_r + 1
            offset_l = max([m[1] for m in mapped_l]) + W
            mapped = mapped_l + [(m[0], offset_l + m[1]) for m in mapped_r]
            ops = []
            for op, a0, a1, a2 in ops_l:
                def update(a):
                    if a == -1 or a < var_in_l:
                        return a
                    else:
                        return a + var_in_r
                ops.append((op, update(a0), update(a1), update(a2)))
            for op, a0, a1, a2 in ops_r:
                def update(a):
                    if a == -1:
                        return a
                    elif a < var_in_r:
                        return a + var_in_l
                    else:
                        return a + var_all_l
                ops.append((op, update(a0), update(a1), update(a2)))
            ops.append(('mul', var_all_l + var_in_r - 1, var_all - 2, var_all - 1))
            return var_in, var_all, mapped, ops
        else:
            raise NotImplementedError(f"Unsupported op: {self.op}")

class Query(BaseModel):
    select: Select
    from_col: str
    where: Predicate
    group_by_col: List[str]
    
    def get_client_mappings(self) -> List[List[int]]:
        # return a list of plaintext vectors to be encrypted
        # each plaintext vector is also a list with len <= CIPHER_SLOT_NUM
        mappings = self.where.get_mappings()
        query_cipher_num = (len(mappings) + CIPHER_SLOT_NUM - 1) // CIPHER_SLOT_NUM
        if query_cipher_num == 1:
            return [mappings]
        else:
            raise NotImplementedError  # later, we need to support alignment in multi-cipher queries

    def write_client_mappings(self, target_loc: str):
        client_mappings = self.get_client_mappings()
        with open(target_loc, "w") as f:
            f.write(str(len(client_mappings)))
            f.write("\n")
            for ms in client_mappings:
                f.write(str(len(ms)))
                f.write("\n")
                for m in ms:
                    f.write(str(m))
                    f.write(" ")
                f.write("\n")
        return client_mappings

    def write_prepare_rots(self, target_loc: str):
        rot_noname_plan = self.where.prepare_rots()
        # format: [task_id] [cipher_id] [offset] [width]
        rot_plan = []
        for cipher_id, offset, width in rot_noname_plan:
            task_id = f"{TASK_PREFIX_PREPARE_ROTS}-{cipher_id}-{offset}-{width}"
            rot_plan.append((task_id, cipher_id, offset, width))
        with open(target_loc, "w") as f:
            f.write(str(len(rot_plan)))
            f.write("\n")
            for task_id, cipher_id, offset, width in rot_plan:
                f.write(f"{task_id},{cipher_id},{offset},{width}\n")
        return rot_plan

    def get_ind_cols(self):
        return self.where.get_ind_cols()
    
    def write_ind_tbl(self, target_folder: str, target_loc: str, group_cnt: Dict[str, int]):
        ind_cols = self.get_ind_cols()
        ind_tbl_plan = []
        # format: [task_id] [file_path] [group_name] [col_name] [expected_record_cnt]
        for group_name, cnt in group_cnt.items():
            for col in ind_cols:
                path = os.path.abspath(f"{target_folder}/{group_name}_{col.upper()}.txt")
                task_id = f"{TASK_PREFIX_READ_IND_TBL}-{group_name}-{col}"
                ind_tbl_plan.append((task_id, path, group_name, col, cnt))
        with open(target_loc, "w") as f:
            f.write(str(len(ind_tbl_plan)))
            f.write("\n")
            for task_id, file_path, group_name, col_name, expected_record_cnt in ind_tbl_plan:
                f.write(f"{task_id},{file_path},{group_name},{col_name},{expected_record_cnt}\n")
        return ind_tbl_plan

    def get_emap_ops(self):
        return self.where.get_emap_ops()
    
    def write_emap(self, target_loc: str, group_cnt: Dict[str, int]):
        W = 1 << MAPPING_BIT_WIDTH
        emap_ops = self.get_emap_ops()
        emap_plan = []
        # format: [task_id] [rot_task_id] [ind_tbl_id] [batch_id] [starting_bit]
        for cipher_id, offset, col, starting_bit in emap_ops:
            for group_name, cnt in group_cnt.items():
                cipher_num = (group_cnt[group_name] + CIPHER_SLOT_NUM - 1) // CIPHER_SLOT_NUM
                for batch_id in range(cipher_num):
                    emap_plan.append((f"{TASK_PREFIX_EMAP}-{cipher_id}-{offset}-{group_name}-{batch_id}",
                                      f"{TASK_PREFIX_PREPARE_ROTS}-{cipher_id}-{offset}-{1 << MAPPING_BIT_WIDTH}", 
                                      f"{TASK_PREFIX_READ_IND_TBL}-{group_name}-{col}", 
                                      batch_id, 
                                      starting_bit))
        with open(target_loc, "w") as f:
            f.write(str(len(emap_plan)))
            f.write("\n")
            for task_id, rot_task_id, ind_tbl_id, batch_id, starting_bit in emap_plan:
                f.write(f"{task_id},{rot_task_id},{ind_tbl_id},{batch_id},{starting_bit}\n")
        return emap_plan
    
    def write_calc_ind_ops(self, target_loc: str):
        var_in, var_all, mapped, ops = self.where.calc_ind_ops()
        with open(target_loc, "w") as f:
            f.write(f"{var_in} {var_all}\n")
            for m in mapped:
                f.write(f"{m[0]} {m[1]}\n")
            f.write(f"{len(ops)}\n")
            for op in ops:
                for o in op:
                    f.write(f"{o} ")
                f.write("\n")
    
    def write_calc_ind_tasks(self, target_loc: str, group_cnt: Dict[str, int]):
        # format: [task_id] [group_id] [batch_id]
        calc_ind_plan = []
        for group_name, cnt in group_cnt.items():
            cipher_num = (group_cnt[group_name] + CIPHER_SLOT_NUM - 1) // CIPHER_SLOT_NUM
            for batch_id in range(cipher_num):
                task_id = f"{TASK_PREFIX_CALC_IND}-{group_name}-{batch_id}"
                calc_ind_plan.append((task_id, group_name, batch_id))
        with open(target_loc, "w") as f:
            f.write(str(len(calc_ind_plan)))
            f.write("\n")
            for task_id, group_id, batch_id in calc_ind_plan:
                f.write(f"{task_id},{group_id},{batch_id}\n")

    
    def write_agg(self, target_folder: str, target_loc: str, group_cnt: Dict[str, int]):
        # format: [task_id] [group_id] [batch_id] [is_cnt] [col] [file_path] [starting_bit]
        agg_plan = []
        agg_cols = self.select.get_agg_cols()
        for group_name, cnt in group_cnt.items():
            cipher_num = (group_cnt[group_name] + CIPHER_SLOT_NUM - 1) // CIPHER_SLOT_NUM
            for batch_id in range(cipher_num):
                task_id_template = f"{TASK_PREFIX_AGG}-{group_name}-{batch_id}"
                agg_plan.append((f"{task_id_template}-cnt", 
                                 group_name, 
                                 batch_id, 
                                 True, "", "", 0))
                for col in agg_cols:
                    path = os.path.abspath(f"{target_folder}/{group_name}_{col[2:].upper() if col.startswith('l_') else col.upper()}.txt")
                    assert os.path.exists(path), f"File not found: {path}"
                    for b in reversed(range(0, DECIMAL_DIGITS, AGG_DIGITS)):
                        task_id = f"{task_id_template}-agg-{col}-{b}"
                        agg_plan.append((task_id, group_name, batch_id, False, col, path, b))
        with open(target_loc, "w") as f:
            f.write(str(len(agg_plan)))
            f.write("\n")
            for task_id, group_id, batch_id, is_cnt, col, file_path, starting_bit in agg_plan:
                f.write(f"{task_id},{group_id},{batch_id},{1 if is_cnt else 0},{col},{file_path},{starting_bit}\n")
        return agg_plan

    def write_plan(self, target_folder: str, group_cnt: Dict[str, int]):
        # client
        self.write_client_mappings(f"{target_folder}/{FILENAME_CLIENT_MAPPINGS}")
        # server
        self.write_prepare_rots(f"{target_folder}/{FILENAME_PREPARE_ROTS}")
        self.write_ind_tbl(target_folder, f"{target_folder}/{FILENAME_READ_IND_TBL}", group_cnt)
        self.write_emap(f"{target_folder}/{FILENAME_EMAP}", group_cnt)
        ops = self.write_calc_ind_ops(f"{target_folder}/{FILENAME_CALC_IND_OPS}")
        self.write_calc_ind_tasks(f"{target_folder}/{FILENAME_CALC_IND_TASK}", group_cnt)
        self.write_agg(target_folder, f"{target_folder}/{FILENAME_AGG}", group_cnt)
