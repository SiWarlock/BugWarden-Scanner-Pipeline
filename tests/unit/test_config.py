"""Tests for configuration management."""

import pytest
from pathlib import Path

from vulnhunter.config.settings import Settings, AnalysisConfig, AnalysisLayer, SeverityLevel


class TestSettings:
    """Test Settings configuration."""
    
    def test_default_settings(self):
        """Test default settings initialization."""
        settings = Settings()
        
        assert settings.project_root == Path.cwd()
        assert settings.log_level == "INFO"
        assert settings.max_workers == 4
        assert settings.use_gpu is False
        
    def test_tool_config_retrieval(self):
        """Test getting tool configurations."""
        settings = Settings()
        
        slither_config = settings.get_tool_config("slither")
        assert slither_config.enabled is True
        assert slither_config.timeout == 300
        assert slither_config.docker_image == "trailofbits/eth-security-toolbox"
        
    def test_path_resolution(self):
        """Test that paths are resolved relative to project root."""
        settings = Settings(
            project_root=Path("/test/project"),
            cache_dir=Path("cache"),
            results_dir=Path("results"),
        )
        
        assert settings.cache_dir == Path("/test/project/cache")
        assert settings.results_dir == Path("/test/project/results")
        
    def test_ensure_directories(self, tmp_path):
        """Test directory creation."""
        settings = Settings(
            project_root=tmp_path,
            cache_dir=Path("cache"),
            results_dir=Path("results"),
            temp_dir=Path("temp"),
        )
        
        settings.ensure_directories()
        
        assert (tmp_path / "cache").exists()
        assert (tmp_path / "results").exists()
        assert (tmp_path / "temp").exists()


class TestAnalysisConfig:
    """Test AnalysisConfig."""
    
    def test_default_config(self):
        """Test default analysis configuration."""
        config = AnalysisConfig()
        
        assert AnalysisLayer.STATIC in config.layers
        assert AnalysisLayer.FUZZING in config.layers
        assert config.parallel_tools is True
        assert config.cache_results is True
        assert config.generate_poc is True
        assert config.min_severity == SeverityLevel.LOW
        
    def test_custom_config(self):
        """Test custom analysis configuration."""
        config = AnalysisConfig(
            layers={AnalysisLayer.STATIC, AnalysisLayer.SYMBOLIC, AnalysisLayer.AI},
            tools=["slither", "mythril"],
            parallel_tools=False,
            generate_poc=False,
            min_severity=SeverityLevel.HIGH,
        )
        
        assert AnalysisLayer.STATIC in config.layers
        assert AnalysisLayer.SYMBOLIC in config.layers
        assert AnalysisLayer.AI in config.layers
        assert AnalysisLayer.FUZZING not in config.layers
        assert config.tools == ["slither", "mythril"]
        assert config.parallel_tools is False
        assert config.generate_poc is False
        assert config.min_severity == SeverityLevel.HIGH
        
    def test_all_layers(self):
        """Test selecting all analysis layers."""
        config = AnalysisConfig(layers={AnalysisLayer.ALL})
        
        assert AnalysisLayer.ALL in config.layers