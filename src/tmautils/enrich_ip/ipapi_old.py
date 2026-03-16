# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Yejin Cho

from pathlib import Path

from tmautils.core import IOHelper


class IPApiUtil:
    def __init__(
        self,
        ipapi_data_dir: Path,
        working_root: Path | None = None,
        data_dir: Path | None = None,
        **kwargs,
    ):
        working_root = IOHelper.handle_working_root_data_dir(
            working_root, data_dir
        )
        self.io_helper = IOHelper(
            self.__class__.__name__,
            working_root=working_root,
            **kwargs,
        )

        # Symbolic link to the ipapi_data_dir inside self.io_helper.raw
        symlink_path = self.io_helper.raw / "ipapi_data"
        # Remove the old symlink if it exists
        if symlink_path.exists():
            if symlink_path.is_symlink():
                symlink_path.unlink()
            else:
                raise FileExistsError(
                    f"{symlink_path} exists and is not a symlink."
                )
        # Create the new symlink
        symlink_path.symlink_to(ipapi_data_dir, target_is_directory=True)
        self.io_helper.logger.info(
            f"Created symlink to {ipapi_data_dir} at {symlink_path}"
        )

        # TODO: Add logic to process the ipapi_data_dir and create a CSV file
        # For now, we will just read the CSV file directly from the raw dir
        db_csv_pathsaved_file = symlink_path / "ip_cache_asn_info.csv"
        if not db_csv_pathsaved_file.exists():
            raise FileNotFoundError(f"{db_csv_pathsaved_file} not found.")
        import pandas
        self.db = pandas.read_csv(
            db_csv_pathsaved_file,
            index_col=0,
            low_memory=False,
        ).to_dict(orient='index')
        self.io_helper.logger.info(
            f"Loaded ipapi dataset from {db_csv_pathsaved_file}"
        )

    def get_asn_info(self, asn: int) -> dict:
        return self.db.get(asn, {})

    def get_asn_name(self, asn: int) -> dict:
        return self.db.get(asn, {}).get("asname", "")

    def is_mobile_proxy_hosting(self, asn: int):
        info = self.get_asn_info(asn)
        return (
            bool(info.get("mobile", False)),
            bool(info.get("proxy", False)),
            bool(info.get("hosting", False)),
        )
