use authenticationservices::SettingsHelper;

#[test]
fn settings_helper_is_a_zero_sized_static_helper() {
    assert_eq!(std::mem::size_of::<SettingsHelper>(), 0);
    let _ = SettingsHelper::is_supported();
}
