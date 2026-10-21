from pathlib import Path
from typing import Optional, Union
import joblib
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from src.core.exceptions import NotFittedError
from src.core.types import FlowBatch


# Encapsulation
class FeaturePipeline:
    """Preprocesses raw flows into standardized scaled batches."""

    def __init__(self) -> None:
        """Initialize empty pipeline encapsulation."""
        self._columns: Optional[list[str]] = None
        self._pipeline: Optional[Pipeline] = None
        self._fitted: bool = False

    @property
    def columns(self) -> list[str]:
        """Return list of expected feature columns."""
        return list(self._columns or [])

    @property
    def is_fitted(self) -> bool:
        """Return fitting status."""
        return self._fitted

    def fit(self, df: pd.DataFrame) -> "FeaturePipeline":
        """Fit internal imputer and scaler on input dataframe."""
        cols = [
            c.strip()
            for c in df.columns
            if c.strip() not in {"Label", "attack_type", "is_attack"}
            and pd.api.types.is_numeric_dtype(df[c])
        ]
        if not cols:
            raise ValueError("No numeric feature columns found to fit pipeline.")

        self._columns = cols
        self._pipeline = Pipeline(
            [
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
            ]
        )
        self._pipeline.fit(df[self._columns])
        self._fitted = True
        return self

    def make_batch(self, df: pd.DataFrame) -> FlowBatch:
        """Transform dataframe into a unified FlowBatch container."""
        if not self._fitted or self._pipeline is None or self._columns is None:
            raise NotFittedError("FeaturePipeline is not fitted yet.")

        cleaned = df.copy()
        cleaned.columns = [c.strip() for c in cleaned.columns]
        if "Fwd Header Length.1" in cleaned.columns:
            cleaned = cleaned.drop(columns=["Fwd Header Length.1"])

        for col in self._columns:
            if col not in cleaned.columns:
                cleaned[col] = 0.0

        sub_df = cleaned[self._columns].replace([np.inf, -np.inf], np.nan)
        scaled_array = self._pipeline.transform(sub_df)
        return FlowBatch(
            raw=cleaned.reset_index(drop=True),
            scaled=scaled_array,
            feature_names=list(self._columns),
        )

    def save(self, path: Union[Path, str]) -> None:
        """Serialize pipeline to disk."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, target)

    @classmethod
    def load(cls, path: Union[Path, str]) -> "FeaturePipeline":
        """Load serialized pipeline from disk."""
        loaded = joblib.load(path)
        if not isinstance(loaded, FeaturePipeline):
            raise TypeError("Loaded object is not a FeaturePipeline instance.")
        return loaded
