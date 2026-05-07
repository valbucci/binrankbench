
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path
from multiprocessing import Queue, Event
import struct
import threading
import time

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from binrankbench.storage.models import (
    Base, Function, CCBHashFingerprint, Catalog1Fingerprint, 
    MachokeHash, FSSOriginalFingerprint, ByteFingerprint,
    FunctionScalars, StrategyMembership, StrategyID
)
from binrankbench.storage.session import _seed_strategy_types
from binrankbench.storage.mp_worker import DBResultCollector
from binrankbench.modules.generate.worker import QueueManager
from binrankbench.modules.generate.result import (
    ResultWrapper, CCBHashResult,
    MachokeResult, Catalog1Result, BytesResult,
    FunctionDetailsResult, FunctionSimSearchResult
)
from binrankbench.modules.ccbhash import CCBHashFeatures


# Ensure all models are loaded
import binrankbench.storage.models.core
import binrankbench.storage.models.dataset
import binrankbench.storage.models.dedup
import binrankbench.storage.models.signatures.ccbhash
import binrankbench.storage.models.signatures.fss
import binrankbench.storage.models.signatures.machoke
import binrankbench.storage.models.signatures.bytes
import binrankbench.storage.models.signatures.catalog1

@pytest.fixture
def engine(tmp_path):
    eng = create_engine(
        f"sqlite:///{tmp_path / 'test.db'}",
        connect_args={"check_same_thread": False},
        echo=False,
    )
    Base.metadata.create_all(eng)
    _seed_strategy_types(eng)
    return eng

def test_db_result_collector_bulk_ingestion(engine):
    # Setup collector with a mocked QueueManager and SharedStats
    qm = QueueManager()
    collector = DBResultCollector(qm, project="test_proj")
    # Speed up tests - batch size of 5
    collector.batch_size = 5 
    
    # Track thread errors
    thread_error = None
    def run_collector():
        nonlocal thread_error
        try:
            collector.run()
        except Exception as e:
            import traceback
            thread_error = (e, traceback.format_exc())

    # Mock get_engine to return our in-memory engine
    with patch("binrankbench.storage.mp_worker.get_engine", return_value=engine):
        
        # Start collector in a background thread
        collector_thread = threading.Thread(target=run_collector)
        collector_thread.start()
        
        try:
            # 1. Prepare various results
            bin_name = "test_bin"
            
            # Catalog1
            # 16 slots, 4 bytes each = 64 bytes hex
            c1_hex = "01000000" * 16 
            res_c1 = ResultWrapper(Path("/tmp"), 0x1000, Catalog1Result(0x1000, True, catalog1=c1_hex), bin_name)
            
            # CCBHash
            ccb_f = CCBHashFeatures(
                name="func1", cfg="cfg1", call_graph="cg1",
                opcodes="op1", var_args="va1", var_locals="vl1",
                ninstructions=10, indegree=1, outdegree=2, nvars=3,
                cc=4, nblocks=5, stackframe=6,
                _ccbhash="00010002000300040102030405060708" 
            )
            res_ccb = ResultWrapper(Path("/tmp"), 0x1001, CCBHashResult(0x1001, True, ccbhash_features=ccb_f), bin_name)
            
            # Machoke
            res_mk = ResultWrapper(Path("/tmp"), 0x1002, MachokeResult(0x1002, True, machoke_line="line1", machoke_digest="bbbb"), bin_name)
            
            # Bytes
            res_bytes = ResultWrapper(Path("/tmp"), 0x1003, BytesResult(0x1003, True, raw_bytes=b"\x11\x22", nibble_sig_mask=b"\xff\x00"), bin_name)
            
            # Scalars
            det = FunctionDetailsResult(0x1004, True, ninstructions=100, nblocks=10, size=500)
            res_det = ResultWrapper(Path("/tmp"), 0x1004, det, bin_name)
            
            # FSS
            fss_res = FunctionSimSearchResult(0x1005, True, fss_plain="11112222333344445555666677778888")
            res_fss = ResultWrapper(Path("/tmp"), 0x1005, fss_res, bin_name)

            # 2. Feed results to queue
            results = [res_c1, res_ccb, res_mk, res_bytes, res_det, res_fss]
            for r in results:
                qm.result_queue.put(r)
            
            # 3. Shutdown collector
            # Wait a bit for processing
            time.sleep(1) 
            qm.collector_shutdown.set()
            collector_thread.join(timeout=5)
            
            if thread_error:
                pytest.fail(f"Collector thread failed:\n{thread_error[1]}")

            # 4. Verify DB contents
            with Session(engine) as session:
                funcs = session.query(Function).all()
                assert len(funcs) == 6
                
                # Check Catalog1
                from binrankbench.storage.models import Catalog1Fingerprint, FunctionCatalog1
                c1_fp = session.query(Catalog1Fingerprint).first()
                assert c1_fp is not None
                
                # Check CCBHash
                from binrankbench.storage.models import CCBHashFingerprint
                ccb_fp = session.query(CCBHashFingerprint).first()
                assert ccb_fp is not None
                
                # Check Machoke
                from binrankbench.storage.models import MachokeHash
                mk_fp = session.query(MachokeHash).first()
                assert mk_fp is not None
                
                # Check Bytes
                from binrankbench.storage.models import ByteFingerprint
                bytes_fp = session.query(ByteFingerprint).first()
                assert bytes_fp is not None
                
                # Check Scalars
                scalars = session.query(FunctionScalars).first()
                assert scalars is not None
                assert scalars.nbbs == 10
                
                # Check FSS
                from binrankbench.storage.models import FSSOriginalFingerprint
                fss_fp = session.query(FSSOriginalFingerprint).first()
                assert fss_fp is not None
                
                # Check memberships
                mems = session.query(StrategyMembership).all()
                assert len(mems) >= 5

        finally:
            qm.collector_shutdown.set()
            if collector_thread.is_alive():
                collector_thread.join(timeout=1)
