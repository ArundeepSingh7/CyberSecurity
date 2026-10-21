from dataclasses import dataclass
from typing import Any
import numpy as np
import pandas as pd


# Abstraction
@dataclass
class FlowBatch:
    """Container holding raw and scaled network flow data."""

    raw: pd.DataFrame
    scaled: np.ndarray
    feature_names: list[str]

    def row(self, i: int) -> dict[str, Any]:
        """Return raw features for row i as a dictionary."""
        return self.raw.iloc[i].to_dict()

    def __len__(self) -> int:
        """Return number of flows in batch."""
        return len(self.raw)
