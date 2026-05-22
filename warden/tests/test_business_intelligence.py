"""
Re-export BI test classes so pytest discovers them under warden/tests/.
The source file lives at warden/business_intelligence/tests/test_intelligence.py
but the CI runner only collects from warden/tests/.
"""
from warden.business_intelligence.tests.test_intelligence import (
    TestBenchmarking,
    TestPredictive,
    TestRepository,
    TestService,
)

__all__ = ["TestBenchmarking", "TestPredictive", "TestRepository", "TestService"]
