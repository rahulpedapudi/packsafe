from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from enum import Enum
from datetime import datetime


class EcosystemType(str, Enum):
    pypi = "pypi"
    npm = "npm"


class PackageMetadata(BaseModel):
    name: str
    version: str
    description: Optional[str] = None
    ecosystem: EcosystemType
    project_urls: Optional[Dict[str, str]] = None
    raw_deps: Optional[List[str]] = None
    dependencies: Optional[List[dict]] = None
    last_release_date: Optional[datetime] = None
