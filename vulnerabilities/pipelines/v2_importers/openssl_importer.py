#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import logging
import shutil
import tempfile
from io import DEFAULT_BUFFER_SIZE
from pathlib import Path
from typing import Iterable
from urllib.parse import urljoin

import dateparser
import requests
from dateutil.parser import parse
from extractcode import ExtractError
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import OpensslVersionRange
from univers.version_range import RpmVersionRange
from univers.versions import OpensslVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes import extractcode_utils
from vulnerabilities.severity_systems import REDHAT_AGGREGATE
from vulnerabilities.utils import build_description
from vulnerabilities.utils import get_item
from vulnerabilities.utils import load_json
from vulntotal import vulntotal_utils


class OpenSSLImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Import OpenSSL Advisories"""

    pipeline_id = "openssl_importer_v2"
    spdx_license_expression = "Apache-2.0"
    importer_name = "OpenSSL Importer V2"

    license_url = "https://github.com/openssl/openssl/blob/master/LICENSE.txt"
    repo_url = "git+https://github.com/openssl/release-metadata/"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self):
        vuln_directory = Path(self.vcs_response.dest_dir) / "secjson"
        return sum(1 for _ in vuln_directory.glob("CVE-*.json"))

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        vuln_directory = Path(self.vcs_response.dest_dir) / "secjson"

        for advisory in vuln_directory.glob("CVE-*.json"):
            yield self.to_advisory_data(advisory)

    def to_advisory_data(self, file: Path) -> Iterable[AdvisoryData]:
        data = load_json(file)
        advisory_text = file.read_text()
        advisory = get_item(data, "containers", "cna")
        description = get_item(advisory, "descriptions", 0, "value")
        title = get_item(advisory, "title")
        date_published = parse(get_item(advisory, "datePublic"))

        affected_packages = []

        for affected in get_item(advisory, "affected", 0, "versions") or []:
            impact_end = affected.get("lessThan")
            impact_start = affected.get("version")

            affected_version_range = OpensslVersionRange(
                constraints=(
                    VersionConstraint(comparator=">=", version=OpensslVersion(string=impact_start)),
                    VersionConstraint(comparator="<", version=OpensslVersion(string=impact_end)),
                )
            )
            fixed_version_range = OpensslVersionRange.from_versions([impact_end])
            affected_packages.append(
                AffectedPackageV2(
                    package=PackageURL(type="openssl", name="openssl"),
                    affected_version_range=affected_version_range,
                    fixed_version_range=fixed_version_range,
                )
            )
