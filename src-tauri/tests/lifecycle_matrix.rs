use piui_lib::lifecycle::LifecycleState;

#[test]
fn generations_advance_once_and_waiting_approvals_fail_closed() {
    let lifecycle = LifecycleState::default();
    assert_eq!(lifecycle.begin_generation().unwrap(), 1);
    lifecycle
        .register_waiting_approval("approval-b".into())
        .unwrap();
    lifecycle
        .register_waiting_approval("approval-a".into())
        .unwrap();
    lifecycle
        .register_waiting_approval("approval-a".into())
        .unwrap();

    assert_eq!(
        lifecycle.fail_waiting_closed().unwrap(),
        ["approval-a", "approval-b"]
    );
    assert!(lifecycle.fail_waiting_closed().unwrap().is_empty());
    assert_eq!(lifecycle.begin_generation().unwrap(), 2);
}
