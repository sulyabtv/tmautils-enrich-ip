# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Sulyab Thottungal Valapu, Yejin Cho

from typing import Any
from pathlib import Path
from ipaddress import ip_address, IPv4Address, IPv6Address
import asyncio
import pandas as pd

from tmautils.core import IOHelper

IP_API_BATCH_URL = "http://ip-api.com/batch"
MAX_IPS_PER_BATCH = 100
MAX_CONCURRENT_REQUESTS = 8
RANDOM_WAIT_MIN = 15
RANDOM_WAIT_MAX = 75
JITTER_MIN = 2
JITTER_MAX = 8
CACHE_DAYS_FRESH = 7

FIELDS = (
    "query",
    "status",
    "message",
    "continent",
    "continentCode",
    "country",
    "countryCode",
    "region",
    "regionName",
    "city",
    "district",
    "zip",
    "lat",
    "lon",
    "timezone",
    "offset",
    "currency",
    "isp",
    "org",
    "as",
    "asname",
    "mobile",
    "proxy",
    "hosting",
)


class IPApiBatchUtil:
    """
    Utility class for interacting with the ip-api.com batch API.

    Args:
        cache_days_fresh (int):
            Number of days to consider a cached result fresh.
            Default is 7 days.

        working_root (Path | None):
            Base directory where the namespace directory will be created.
            If None, the current working directory will be used.

        data_dir (Path | None):
            Deprecated alias for `working_root`.

        **kwargs (dict):
            Additional arguments for IOHelper.
            See the IOHelper class for more details.
    """

    def __init__(
        self,
        cache_days_fresh: int = CACHE_DAYS_FRESH,
        working_root: Path | None = None,
        data_dir: Path | None = None,
        **kwargs,
    ):
        working_root = IOHelper.handle_working_root_data_dir(
            working_root, data_dir
        )
        self.io_helper = IOHelper.init_with_dirs(
            self.__class__.__name__,
            dirs={"processed", "logs"},
            working_root=working_root,
            **kwargs,
        )

        self.cache_days_fresh = cache_days_fresh

        # Set up snapshot directory if it doesn't exist
        snapshot_dir = self.io_helper.processed / "latest"
        snapshot_dir.mkdir(parents=True, exist_ok=True)

        # Read existing snapshot if it exists
        self._load_cache()

        self.io_helper.logger.info(
            f"Initialized IPApiBatchUtil with cache_days_fresh: {self.cache_days_fresh}"
        )

    @staticmethod
    def _normalize_ip(ip: str | IPv4Address | IPv6Address):
        # parse & re‐stringify in a standardized way
        if isinstance(ip, (IPv4Address, IPv6Address)):
            return str(ip)
        return str(ip_address(ip))

    def _load_cache(self):
        snapshot_path = self.io_helper.processed / "latest" / "current.csv"
        if snapshot_path.exists():
            self.current = pd.read_csv(
                snapshot_path,
                encoding="utf-8",
                low_memory=False,
            )
            self.current = self.current.loc[
                :, ~self.current.columns.duplicated()
            ]

            # Standardize the "query" column
            self.current["query"] = self.current["query"].map(
                self._normalize_ip
            )

            # Fix up "last_queried" column
            if "last_queried" not in self.current.columns:
                self.current["last_queried"] = pd.Series(
                    pd.NaT, index=self.current.index, dtype="datetime64[ns]"
                )
            else:
                self.current["last_queried"] = pd.to_datetime(
                    self.current["last_queried"], format="%Y-%m-%d", errors="coerce"
                )
        else:
            self.current = pd.DataFrame(
                {c: pd.Series(dtype="object") for c in list(FIELDS)}
            )
            self.current["last_queried"] = pd.Series(dtype="datetime64[ns]")

        # Drop stale rows
        self._drop_stale_cache_rows()

        self.io_helper.logger.info(
            f"Loaded cache with {len(self.current)} fresh entries "
            f"from {snapshot_path}"
        )

    def _drop_stale_cache_rows(self):
        from datetime import date, timedelta

        cutoff = date.today() - timedelta(days=self.cache_days_fresh)
        stale = self.current["last_queried"].dt.date < cutoff
        self.current = self.current.loc[~stale].reset_index(drop=True)

        if stale.sum() > 0:
            self.io_helper.logger.info(
                f"Dropped {stale.sum()} stale rows from cache. "
                f"Remaining entries: {len(self.current)}"
            )

    async def get_batch_api(
        self,
        ips: list[str | IPv4Address | IPv6Address],
        max_retry: int = 8,
        save_cache: bool = True,
    ):
        """
        Query ip-api.com's batch API for a list of IP addresses.

        NOTE: This function instantiates its own `asyncio.Semaphore` internally
        to throttle requests. If you invoke it multiple times concurrently
        (or from separate event loops), each call will create its own semaphore
        and you may exceed your intended global limit. Therefore, only call
        `get_batch_api()` once at a time per loop to guarantee a true cap of
        `max_concurrent_requests`.

        Args:
            ips (list[str | IPv4Address | IPv6Address]):
                List of IP addresses to query.

            max_retry (int):
                Maximum number of retries for each batch.
                Default is 5.

            save_cache (bool):
                Whether to save the results to a cache file.
                Default is True.

        Returns:
            df (pd.DataFrame):
                DataFrame containing the results for the requested IPs.
        """
        import aiohttp
        from random import randint

        # Standardize IPs
        ips_str = [self._normalize_ip(ip) for ip in ips]

        # Split the list of IPs into batches of MAX_IPS_PER_BATCH
        batches = [
            ips_str[i:i+MAX_IPS_PER_BATCH]
            for i in range(0, len(ips_str), MAX_IPS_PER_BATCH)
        ]

        ipapi_batch_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

        results: dict[str, Any] = {}

        async with aiohttp.ClientSession() as session:
            async def _fetch_one_batch(batch: list[str]):
                for attempt in range(1, max_retry + 1):
                    async with ipapi_batch_semaphore:
                        try:
                            resp = await session.post(
                                f"{IP_API_BATCH_URL}?fields={','.join(FIELDS)}",
                                json=batch
                            )
                        except aiohttp.ClientConnectionError as e:
                            # We do not know how long to wait
                            wait = randint(RANDOM_WAIT_MIN, RANDOM_WAIT_MAX)
                            self.io_helper.logger.warning(
                                f"ConnErr on batch {batch[:3]}... "
                                f"(attempt {attempt}/{max_retry}): {e}. "
                                f"retrying in {wait:.0f}s"
                            )
                            if attempt < max_retry:
                                await asyncio.sleep(wait)
                            continue

                        if resp.status != 200:
                            ttl = int(resp.headers.get("X-Ttl", "0"))
                            rl = int(resp.headers.get("X-Rl", "0"))
                            if ttl == 0 and rl == 0:
                                # We don't know how long to wait
                                ttl = randint(RANDOM_WAIT_MIN, RANDOM_WAIT_MAX)
                            else:
                                ttl += randint(JITTER_MIN, JITTER_MAX)
                            self.io_helper.logger.info(
                                f"Got HTTP {resp.status} on batch {batch[:3]}... "
                                f"(attempt {attempt}/{max_retry}), retrying in {ttl}s"
                            )
                            if attempt < max_retry:
                                await asyncio.sleep(ttl)
                            continue

                        data = await resp.json()
                        for entry in data:
                            results[entry["query"]] = entry

                        self.io_helper.logger.info(
                            f"Batch {batch[:3]}... fetched successfully "
                            f"(attempt {attempt}/{max_retry})"
                        )

                        return

                # If we reach here, we are out of attempts
                self.io_helper.logger.warning(
                    f"Batch {batch[:3]}... failed after {max_retry} attempts"
                )

            tasks = [asyncio.create_task(_fetch_one_batch(b)) for b in batches]
            await asyncio.gather(*tasks)

        # Convert the result into a DataFrame
        results_df = pd.DataFrame.from_dict(results, orient='index')
        results_df.index.name = "query"
        if "query" in results_df.columns:
            results_df = results_df.drop(columns=["query"])
        results_df.reset_index(inplace=True)

        # Ensure all expected columns are present
        for col in FIELDS:
            if col not in results_df.columns:
                results_df[col] = pd.NA

        # Save the results to a cache file
        if save_cache:
            self._cache_results(results_df)

        return results_df

    def _cache_results(
        self,
        results: pd.DataFrame,
    ):
        from datetime import date

        date_str = date.today().isoformat()
        results["last_queried"] = pd.to_datetime(date_str, format="%Y-%m-%d")

        # Set up history directory
        history_dir = self.io_helper.processed / "history" / date_str
        history_dir.mkdir(parents=True, exist_ok=True)

        # Drop stale rows from the current cache
        self._drop_stale_cache_rows()

        def _row_changed(r):
            # If the row is new (no old data), return True
            if pd.isna(r["last_queried_old"]):
                return True

            for f in FIELDS:
                # Skip the key field "query"
                if f == "query":
                    continue

                # If this column did not exist before, return True
                old_key = f + "_old"
                if old_key not in r:
                    return True

                new_val, old_val = r[f], r[old_key]
                # If both are NaN, they are considered unchanged
                if pd.isna(new_val) and pd.isna(old_val):
                    continue
                # If one is NaN and the other is not, return True
                if pd.isna(new_val) != pd.isna(old_val):
                    return True

                # If both are not NaN, check if they are different
                if new_val != old_val:
                    return True
            return False

        # Identify rows that have changed
        merged = results.merge(
            self.current, on="query", how="left", suffixes=("", "_old")
        )
        changed = merged[
            merged.apply(_row_changed, axis=1)
        ][list(FIELDS) + ["last_queried"]]

        if not changed.empty:
            date_existing = list(
                history_dir.glob(f"changes_{date_str}_*.csv")
            )
            idx = len(date_existing) + 1
            target = history_dir / f"changes_{date_str}_{idx}.csv"
            changed.to_csv(
                target,
                index=False,
                encoding="utf-8",
            )
            self.io_helper.logger.info(
                f"Saved {len(changed)} changes to {target}"
            )

        # ensure both have exactly the same columns (in the same order)
        data_cols = [c for c in results.columns if c != "query"]
        cur_idx = self.current.set_index("query").reindex(columns=data_cols)
        new_idx = results.set_index("query").reindex(columns=data_cols)
        new_entries = new_idx.loc[~new_idx.index.isin(cur_idx.index)]

        # Save the current snapshot
        self.current = pd.concat(
            [cur_idx, new_entries], sort=False
        ).reset_index()
        self.current.to_csv(
            self.io_helper.processed / "latest" / "current.csv",
            index=False,
            encoding="utf-8",
        )

        self.io_helper.logger.info(
            f"Cached {len(new_entries)} new entries to current snapshot. "
            f"Total entries now: {len(self.current)}"
        )

    def get_batch(
        self,
        ips: list[str | IPv4Address | IPv6Address],
    ) -> pd.DataFrame:
        """
        Get a batch of IP addresses from the cache or API.

        Args:
            ips (list[str | IPv4Address | IPv6Address]):
                List of IP addresses to query.

        Returns:
            df (pd.DataFrame):
                DataFrame containing the results for the requested IPs.
        """
        # Standardize IPs
        ips_str = [self._normalize_ip(ip) for ip in ips]

        # If a result is fresh, use it
        self._drop_stale_cache_rows()
        cached = self.current.loc[
            self.current["query"].isin(ips_str), list(FIELDS)
        ]

        # Determine which IPs need querying
        cached_set = set(cached["query"])
        to_query = [ip for ip in ips_str if ip not in cached_set]

        # Query the API for the remaining IPs
        new_df = pd.DataFrame(columns=list(FIELDS))
        if to_query:
            self.io_helper.logger.info(
                f"Cached result not found for {len(to_query)} IPs, querying API"
            )
            fetched = asyncio.run(self.get_batch_api(to_query))
            new_df = fetched[list(FIELDS)]

        # Combine and return
        if new_df.empty:
            return cached.reset_index(drop=True)
        cached = cached.reindex(columns=list(FIELDS))
        new_df = new_df.reindex(columns=list(FIELDS))
        return pd.concat([cached, new_df], ignore_index=True)
