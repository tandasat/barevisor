//! Build the package as a WDM driver.

fn main() -> Result<(), wdk_build::ConfigError> {
    let mut config = wdk_build::Config::from_env_auto()?;
    config.driver_config = wdk_build::DriverConfig::Wdm;
    config.configure_binary_build()
}
