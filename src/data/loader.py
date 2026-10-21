from pathlib import Path
from typing import Optional
import numpy as np
import pandas as pd
import config
from src.core.exceptions import DataLoadError
from src.data.labels import map_label


# Encapsulation
def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Clean column names, handle infs, and drop duplicates."""
    df.columns = [c.strip() for c in df.columns]
    if "Fwd Header Length.1" in df.columns:
        df = df.drop(columns=["Fwd Header Length.1"])
    df = df.loc[:, ~df.columns.duplicated()]
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    df = df.drop_duplicates()
    return df


# Encapsulation
def load_raw_dataset(raw_dir: Optional[Path] = None, user_csv: Optional[Path] = None) -> pd.DataFrame:
    """Load, clean, map labels, and sample raw CICIDS2017 CSVs and user dataset."""
    target_dir = raw_dir or config.RAW_DATA_DIR
    csv_files = sorted(list(target_dir.glob("*.csv")))
    if not csv_files:
        raise DataLoadError(f"No CSV files found in {target_dir}")

    print(f"Loading raw CICIDS2017 dataset from {target_dir} ({len(csv_files)} files)...")

    # Fast targeted mapping by file
    class_targets: dict[str, tuple[str, int]] = {
        "DDoS": ("*DDos*.csv", 5000),
        "PortScan": ("*PortScan*.csv", 5000),
        "Bot": ("*Morning*.csv", 3000),
        "WebAttack": ("*WebAttacks*.csv", 3000),
        "BruteForce": ("*Tuesday*.csv", 5000),
        "DoS": ("*Wednesday*.csv", 5000),
        "BENIGN": ("*Monday*.csv", 6000),
    }

    dfs: list[pd.DataFrame] = []

    # 1. Targeted extraction from MachineLearningCVE
    for target_class, (pattern, quota) in class_targets.items():
        matched = list(target_dir.glob(pattern))
        if not matched:
            matched = csv_files

        collected = 0
        for f in matched:
            if collected >= quota:
                break
            try:
                for chunk in pd.read_csv(f, chunksize=35000, low_memory=False, encoding_errors="replace"):
                    chunk = clean_dataframe(chunk)
                    if "Label" not in chunk.columns:
                        continue
                    chunk["attack_type"] = chunk["Label"].apply(map_label)
                    subset = chunk[chunk["attack_type"] == target_class]
                    if not subset.empty:
                        take = subset.iloc[: (quota - collected)]
                        dfs.append(take)
                        collected += len(take)
                        if collected >= quota:
                            break
            except Exception as e:
                print(f"  Warning reading {f.name}: {e}")

        print(f"  - Extracted '{target_class}': {collected:,} samples from {pattern}")

    # 2. Also load user's specific test_cicids_labeled.csv if present
    user_file = user_csv or Path(r"C:\Users\arund\Downloads\test_cicids_labeled.csv")
    if not user_file.exists():
        user_file = config.DATA_DIR / "raw" / "test_cicids_labeled.csv"
    if user_file.exists():
        try:
            print(f"  - Integrating user dataset: {user_file.name}...")
            u_df = pd.read_csv(user_file, low_memory=False, encoding_errors="replace")
            u_df = clean_dataframe(u_df)
            if "Label" in u_df.columns:
                u_df["attack_type"] = u_df["Label"].apply(map_label)
            u_df = u_df.dropna(subset=["attack_type"]).reset_index(drop=True)
            dfs.append(u_df)
            print(f"  - Successfully added {len(u_df)} user-labeled samples!")
        except Exception as e:
            print(f"  Warning reading user csv: {e}")

    if not dfs:
        raise DataLoadError("No valid data frames loaded from raw CSVs.")

    final_df = pd.concat(dfs, ignore_index=True)
    final_df = final_df.drop_duplicates(
        subset=[c for c in final_df.columns if c not in {"Label", "attack_type", "is_attack"}]
    )
    final_df = final_df.sample(frac=1.0, random_state=config.RANDOM_SEED).reset_index(drop=True)
    final_df["is_attack"] = (final_df["attack_type"] != "BENIGN").astype(int)
    return final_df
