"""
Module Runner - Executes analysis modules on PCAP files
- Queue-based job management
- Worker threads for parallel execution
- Auto-discovery of modules
"""

import queue
import threading
import logging
import importlib
import pkgutil
from pathlib import Path
from typing import List, Optional, Dict, Type
from dataclasses import dataclass
import time

from .base import BaseModule, Summary

logger = logging.getLogger(__name__)


@dataclass
class AnalysisJob:
    """Analysis job to be processed"""
    pcap_path: str
    interface: str
    time_window: str
    priority: int = 0  # Lower = higher priority
    
    def __lt__(self, other):
        return self.priority < other.priority


class ModuleRunner:
    """
    Manages and executes analysis modules
    - Discovers available modules
    - Queues analysis jobs
    - Runs modules in worker threads
    """
    
    def __init__(
        self,
        output_dir: str,
        enabled_modules: List[str] = None,
        num_workers: int = 2,
        max_queue_size: int = 100,
    ):
        """
        Args:
            output_dir: Base directory for module output
            enabled_modules: List of module names to enable (None = all)
            num_workers: Number of worker threads
            max_queue_size: Max jobs in queue
        """
        self.output_dir = Path(output_dir)
        self.enabled_module_names = enabled_modules
        self.num_workers = num_workers
        
        # Module registry
        self._modules: Dict[str, BaseModule] = {}
        
        # Job queue (priority queue)
        self._job_queue: queue.PriorityQueue = queue.PriorityQueue(maxsize=max_queue_size)
        
        # Worker threads
        self._workers: List[threading.Thread] = []
        self._running = False
        self._stop_event = threading.Event()
        
        # Stats
        self._jobs_completed = 0
        self._jobs_failed = 0
        self._lock = threading.Lock()
    
    def register_module(self, module: BaseModule):
        """Register a module"""
        self._modules[module.name] = module
        logger.info(f"Registered module: {module.name}")
    
    def discover_modules(self, package_path: str = None):
        """
        Discover and register modules from a package
        Looks for classes that inherit from BaseModule
        """
        if package_path is None:
            # Default: look in modules/ directory
            package_path = str(Path(__file__).parent)
        
        # Import all submodules
        package = Path(package_path)
        
        for item in package.iterdir():
            if item.is_dir() and (item / '__init__.py').exists():
                module_name = item.name
                
                # Skip special directories
                if module_name.startswith('_'):
                    continue
                
                try:
                    # Try to import the module
                    mod = importlib.import_module(f'modules.{module_name}')
                    
                    # Look for BaseModule subclasses
                    for attr_name in dir(mod):
                        attr = getattr(mod, attr_name)
                        if (isinstance(attr, type) and 
                            issubclass(attr, BaseModule) and 
                            attr is not BaseModule):
                            # Instantiate and register
                            instance = attr()
                            self.register_module(instance)
                
                except Exception as e:
                    logger.warning(f"Error loading module {module_name}: {e}")
    
    def get_enabled_modules(self) -> List[BaseModule]:
        """Get list of enabled modules"""
        if self.enabled_module_names is None:
            return list(self._modules.values())
        
        return [
            self._modules[name] 
            for name in self.enabled_module_names 
            if name in self._modules
        ]
    
    def get_available_modules(self) -> List[str]:
        """Get list of available module names"""
        return list(self._modules.keys())
    
    def queue_analysis(self, pcap_path: str, interface: str, time_window: str, priority: int = 0):
        """
        Queue a PCAP file for analysis
        
        Args:
            pcap_path: Path to PCAP file
            interface: Network interface name
            time_window: Time window string (YYYY-MM-DD_HH)
            priority: Job priority (lower = higher priority)
        """
        job = AnalysisJob(
            pcap_path=pcap_path,
            interface=interface,
            time_window=time_window,
            priority=priority
        )
        
        try:
            self._job_queue.put_nowait(job)
            logger.info(f"Queued analysis: {pcap_path}")
        except queue.Full:
            logger.warning(f"Analysis queue full, dropping: {pcap_path}")
    
    def _worker_loop(self, worker_id: int):
        """Worker thread main loop"""
        logger.info(f"Worker {worker_id} started")
        
        while not self._stop_event.is_set():
            try:
                # Get job with timeout (to check stop event)
                try:
                    job = self._job_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                
                # Process job
                self._process_job(job, worker_id)
                
                # Mark done
                self._job_queue.task_done()
                
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")
        
        logger.info(f"Worker {worker_id} stopped")
    
    def _process_job(self, job: AnalysisJob, worker_id: int):
        """Process a single analysis job"""
        logger.info(f"Worker {worker_id} processing: {job.pcap_path}")
        
        # Check if file exists
        if not Path(job.pcap_path).exists():
            logger.warning(f"PCAP file not found: {job.pcap_path}")
            with self._lock:
                self._jobs_failed += 1
            return
        
        # Run enabled modules
        for module in self.get_enabled_modules():
            try:
                start_time = time.time()
                
                summary = module.analyze(
                    pcap_path=job.pcap_path,
                    output_dir=str(self.output_dir),
                    interface=job.interface,
                    time_window=job.time_window
                )
                
                duration = time.time() - start_time
                logger.info(
                    f"Module {module.name} completed: "
                    f"{summary.total_hits} hits in {duration:.2f}s"
                )
                
            except Exception as e:
                logger.error(f"Module {module.name} failed: {e}")
        
        with self._lock:
            self._jobs_completed += 1
    
    def start(self):
        """Start worker threads"""
        if self._running:
            return
        
        self._running = True
        self._stop_event.clear()
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Start workers
        for i in range(self.num_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                args=(i,),
                daemon=True,
                name=f"ModuleWorker-{i}"
            )
            worker.start()
            self._workers.append(worker)
        
        logger.info(f"ModuleRunner started with {self.num_workers} workers")
    
    def stop(self, wait: bool = True, timeout: float = 10.0):
        """
        Stop worker threads
        
        Args:
            wait: Wait for pending jobs to complete
            timeout: Max time to wait
        """
        if not self._running:
            return
        
        self._running = False
        self._stop_event.set()
        
        if wait:
            # Wait for queue to empty
            try:
                self._job_queue.join()
            except Exception:
                pass
        
        # Wait for workers
        for worker in self._workers:
            worker.join(timeout=timeout / len(self._workers) if self._workers else timeout)
        
        self._workers.clear()
        logger.info("ModuleRunner stopped")
    
    @property
    def queue_size(self) -> int:
        """Current queue size"""
        return self._job_queue.qsize()
    
    @property
    def jobs_completed(self) -> int:
        return self._jobs_completed
    
    @property
    def jobs_failed(self) -> int:
        return self._jobs_failed
    
    def get_status(self) -> dict:
        """Get runner status"""
        return {
            "running": self._running,
            "workers": len(self._workers),
            "queue_size": self.queue_size,
            "jobs_completed": self._jobs_completed,
            "jobs_failed": self._jobs_failed,
            "enabled_modules": [m.name for m in self.get_enabled_modules()],
            "available_modules": self.get_available_modules(),
        }


def create_runner(
    output_dir: str,
    enabled_modules: List[str] = None,
    auto_discover: bool = True,
) -> ModuleRunner:
    """
    Create and configure a ModuleRunner
    
    Args:
        output_dir: Output directory for results
        enabled_modules: List of module names to enable
        auto_discover: Auto-discover modules in modules/ directory
    
    Returns:
        Configured ModuleRunner instance
    """
    runner = ModuleRunner(
        output_dir=output_dir,
        enabled_modules=enabled_modules,
    )
    
    if auto_discover:
        runner.discover_modules()
    
    return runner

