from binrankbench.modules.ccbhash import CCBHashBuilder
from binrankbench.common.types import (R2FunctionInfoIn, R2ZignatureIn, 
                                   R2CodeInfoIn, R2CallGraph)


def test_ccbhash_builder(finfo: R2FunctionInfoIn, zignature: R2ZignatureIn, 
                         cfg: R2CodeInfoIn, global_call_graph: R2CallGraph):
    features = CCBHashBuilder.build(finfo, zignature, cfg, global_call_graph)
    digest = features.ccbhash
    assert len(digest.hash_list) == 13
