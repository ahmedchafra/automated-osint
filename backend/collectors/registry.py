import importlib
import pkgutil
import inspect
from typing import Dict, Type

from collectors.base import BaseCollector

class CollectorRegistry:
    def __init__(self):
        self._collectors: Dict[str, Type[BaseCollector]] = {}

    def register(self, name: str, collector_cls: Type[BaseCollector]):
        self._collectors[name] = collector_cls

    def get_collector(self, name: str) -> Type[BaseCollector]:
        if name not in self._collectors:
            raise ValueError(f"Collector {name} not found")
        return self._collectors[name]

    def get_all_collectors(self) -> Dict[str, Type[BaseCollector]]:
        return self._collectors

    def get_collectors_by_vector(self, vector: str) -> Dict[str, Type[BaseCollector]]:
        return {
            name: cls for name, cls in self._collectors.items() 
            if cls.metadata.vector == vector
        }

    def discover_collectors(self, package_name: str = "collectors"):
        """Automatically discover and register all BaseCollector subclasses in a package."""
        package = importlib.import_module(package_name)
        
        for finder, module_name, is_pkg in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
            # Skip the base and registry modules themselves to avoid recursion/errors
            if module_name.endswith('.base') or module_name.endswith('.registry'):
                continue
                
            try:
                module = importlib.import_module(module_name)
                
                for _, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and 
                        issubclass(obj, BaseCollector) and 
                        obj != BaseCollector and 
                        not inspect.isabstract(obj)):
                        
                        if hasattr(obj, 'metadata') and obj.metadata is not None:
                            try:
                                self.register(obj.metadata.name, obj)
                            except Exception as e:
                                print(f"Failed to register {obj.__name__}: {e}")
                        else:
                            print(f"Skipping {obj.__name__}: Missing metadata")
            except ImportError:
                continue

# Global registry instance
registry = CollectorRegistry()

# Initialize registry
registry.discover_collectors()
