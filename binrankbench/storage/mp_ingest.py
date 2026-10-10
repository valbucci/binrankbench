"""Multiprocess ingestion orchestrator: launches poster, runner, and collector processes."""

import logging
import time
from pathlib import Path
from multiprocessing import Process, Queue
from typing import Optional

from binrankbench.modules.generate.worker import QueueManager, run_task_runner, run_logging_manager
from binrankbench.modules.generate.logging import setup_main_logging, get_logger, initialize_logging_config, get_logging_config
from binrankbench.modules.generate.stats import SharedStats
from binrankbench.modules.generate.dashboard import Dashboard
from binrankbench.storage.mp_worker import run_db_result_collector, run_ingest_poster

def ingest_directory_mp(
    raw_data_dir: Path,
    project: str,
    datasets: list[str],
    strategies: list[str],
    n_runners: int = 4,
    n_posters: int = 1,
    overwrite: bool = False,
):
    logger = get_logger("mp_ingest")
    logger.setLevel(logging.INFO)
    logger.info(f"Starting multiprocessing ingestion with {n_runners} runners and {n_posters} posters")

    raw_data_dir = Path(raw_data_dir)
    
    bin_names = set()
    for p in raw_data_dir.iterdir():
        if not p.is_file() and not p.is_dir():
            continue
        name = p.name
        for suffix in ("_cfg.json", "_func-cfg.jsonl", "_finfo.json", "_zigs.json", "_cg.json", "_bininfo.json", "_bytes.tar", "_bytes-masked.tar"):
            if name.endswith(suffix):
                bin_names.add(name[:-len(suffix)])
                break
        if p.is_dir() and name.endswith("_func-cfg"):
            bin_names.add(name[:-len("_func-cfg")])
        for pfix in ("_bytes", "_bytes-masked"):
            if p.is_dir() and name.endswith(pfix):
                bin_names.add(name[:-len(pfix)])
                
    sorted_bins = sorted(bin_names)
    binary_paths = [raw_data_dir / b for b in sorted_bins]
    logger.info(f"Discovered {len(binary_paths)} unique binaries for ingestion in {raw_data_dir}")

    log_queue = Queue(maxsize=10000)
    dashboard_queue = Queue(maxsize=1000)
    
    # Set up the base binrankbench logger (covers hex, utils, ccbhash etc.)
    # The generate logger is handled separately by setup_main_logging below.
    from binrankbench.common.logging import setup_console_logging
    setup_console_logging()

    initialize_logging_config(tui_enabled=True, console_level="INFO", file_level="INFO")
    logger_manager = setup_main_logging(log_queue)
    
    logging_config = get_logging_config()
    logging_process = Process(
        target=run_logging_manager,
        args=(log_queue, dashboard_queue, True, logging_config.console_level, logging_config.file_level, None),
        name="LoggingManager"
    )
    logging_process.start()
    time.sleep(0.5)

    queue_manager = QueueManager(maxsize_tasks=10000, maxsize_results=100000)
    shared_stats = SharedStats(n_posters=n_posters, n_runners=n_runners)

    logger.info(f"Starting {n_runners} TaskRunner workers...")
    runner_processes = []
    for i in range(n_runners):
        p = Process(
            target=run_task_runner,
            args=(i, queue_manager, log_queue, shared_stats, raw_data_dir),
            name=f"TaskRunner-{i}"
        )
        p.start()
        runner_processes.append(p)
    
    logger.info("Starting DBResultCollector...")
    collector_process = Process(
        target=run_db_result_collector,
        args=(queue_manager, log_queue, project, shared_stats),
        name="DBResultCollector"
    )
    collector_process.start()

    logger.info(f"Starting {n_posters} IngestTaskPoster workers...")
    poster_processes = []
    for i in range(n_posters):
        p = Process(
            target=run_ingest_poster,
            args=(i, project, raw_data_dir, Path("/tmp"), queue_manager, log_queue, shared_stats, strategies, datasets, overwrite),
            name=f"IngestTaskPoster-{i}"
        )
        p.start()
        poster_processes.append(p)

    n_queued = 0
    for bp in binary_paths:
        queue_manager.binary_queue.put(bp)
        n_queued += 1

    logger.info(f"Queued {n_queued} binaries for processing. Waiting for posters to finish...")
    for _ in range(n_posters):
        queue_manager.binary_queue.put(None)
        
    dashboard = Dashboard(
        shared_stats=shared_stats,
        queue_manager=queue_manager,
        log_queue=dashboard_queue,
        title="INGESTION",
        throughput_label="DB Inserts/sec"
    )

    try:
        dashboard.start()
        completed_markers = set()
        
        while any(p.is_alive() for p in poster_processes + runner_processes + [collector_process]):
            snapshot = shared_stats.get_snapshot()
            current_tasks_completed = snapshot.tasks_succeeded + snapshot.tasks_failed
            
            # Identify active binaries and mark complete ones
            if snapshot.binary_progress:
                for name, prog in snapshot.binary_progress.items():
                    if prog["expected"] > 0 and prog["done"] >= prog["expected"]:
                        if name not in completed_markers:
                            done_marker = raw_data_dir / f"{name}.ingest_done"
                            try:
                                done_marker.touch(exist_ok=True)
                                completed_markers.add(name)
                                logger.debug(f"Created .ingest_done asynchronously for {name}")
                            except Exception as e:
                                logger.warning(f"Failed to create .ingest_done for {name}: {e}")
            
            all_posters_finished = all(not p.is_alive() for p in poster_processes)
            
            # Check for poster crashes
            for p in poster_processes:
                if not p.is_alive() and p.exitcode is not None and p.exitcode != 0:
                    logger.error(f"POSTER CRASH DETECTED: {p.name} exited with code {p.exitcode}")
                    # We continue because other posters might still be alive and working
            
            # Only signal all_posters_done when every poster process has truly exited.
            if all_posters_finished and not queue_manager.all_posters_done.is_set():
                logger.info("All TaskPoster processes have finished. Signaling TaskRunners.")
                queue_manager.all_posters_done.set()

            if queue_manager.all_posters_done.is_set() and not any(p.is_alive() for p in runner_processes):
                if not queue_manager.collector_shutdown.is_set():
                    logger.info("All TaskRunners have finished. Signaling ResultCollector.")
                    queue_manager.collector_shutdown.set()

            time.sleep(1)
            
        for p in poster_processes:
            p.join()
        queue_manager.all_posters_done.set()
        
        for p in runner_processes:
            p.join()
        queue_manager.collector_shutdown.set()
            
        collector_process.join()

    except KeyboardInterrupt:
        logger.warning("KeyboardInterrupt intercepted! Requesting graceful shutdown...")
        queue_manager.all_runners_shutdown.set()
        queue_manager.collector_shutdown.set()
        queue_manager.all_posters_done.set()
        
        # Give processes up to 3 seconds to cleanly wrap up and release DB connections
        end_time = time.time() + 3.0
        active_procs = poster_processes + runner_processes + [collector_process]
        while time.time() < end_time and any(p.is_alive() for p in active_procs):
            time.sleep(0.1)
            
        for p in active_procs:
            if p.is_alive():
                logger.warning(f"Force terminating lingering process: {p.name}")
                p.terminate()

    finally:
        dashboard.stop()
        log_queue.put(None)
        logging_process.join(timeout=2.0)
        logger_manager.cleanup()
        queue_manager.close()
        logger.info("Multiprocess Ingestion Completed Successfully!")
