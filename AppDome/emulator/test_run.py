"""Regression checks for the stale-window / inherited-Frida-session failure."""

import time
from contextlib import ExitStack
import unittest
from types import SimpleNamespace
from unittest.mock import patch, Mock

import run


class ResponsivenessTests(unittest.TestCase):
    def setUp(self):
        self.session = SimpleNamespace(is_detached=False)
        self.health = {"heartbeat": time.monotonic(), "touches": 0, "error": None}

    def test_dead_main_is_rejected_even_when_frida_remains_attached(self):
        # Only an orphaned child remains; the old verifier reported PASS here.
        with patch.object(run, "app_processes", return_value={124: 1}):
            with self.assertRaisesRegex(RuntimeError, "123 exited"):
                run.require_alive(self.session, 123, self.health)

    def test_live_pid_does_not_prove_main_thread_is_responsive(self):
        self.health["heartbeat"] -= 10
        with patch.object(run, "app_processes", return_value={123: 305}):
            with self.assertRaisesRegex(RuntimeError, "Main thread stopped"):
                run.require_alive(self.session, 123, self.health)

    def test_focused_window_and_adb_success_do_not_prove_keyboard_delivery(self):
        command = Mock()
        command.stdout = "mInputShown=false"
        def acknowledge_touch(*_args, **_kwargs):
            self.health["touches"] += 1
            return command

        with patch.object(run, "app_processes", return_value={123: 305}), \
                patch.object(run, "focused_window", return_value=run.PACKAGE), \
                patch.object(run, "adb", side_effect=acknowledge_touch), \
                patch.object(run.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "show the keyboard"):
                run.verify(self.session, 123, self.health)

    def test_blocked_rpc_is_cancelled(self):
        import threading

        def blocked(*, cancellable):
            cancelled = threading.Event()
            handler = cancellable.connect(cancelled.set)
            try:
                self.assertTrue(cancelled.wait(1), "RPC cancellation never arrived")
                cancellable.raise_if_cancelled()
            finally:
                cancellable.disconnect(handler)

        with self.assertRaisesRegex(TimeoutError, "test RPC timed out"):
            run.frida_call("test RPC", blocked, timeout=0.02)

    def test_failed_script_load_detaches_session_without_hiding_failure(self):
        script = Mock()
        script.load.side_effect = RuntimeError("load failed")
        session = Mock(is_detached=False)
        session.create_script.return_value = script
        device = Mock()
        device.attach.return_value = session
        with self.assertRaisesRegex(RuntimeError, "load failed"):
            run.install_hooks(device, 123)
        session.detach.assert_called_once()

    def test_suspended_process_resumes_only_after_script_load(self):
        order = []
        callbacks = {}
        script = Mock()
        script.on.side_effect = lambda _event, callback: callbacks.update(
            message=callback
        )
        script.load.side_effect = lambda **_kwargs: (
            order.append("load"),
            callbacks["message"](
                {"payload": {"tag": "appdome-ready"}}, None
            ),
        )
        session = Mock(is_detached=False)
        session.create_script.return_value = script
        device = Mock()
        device.attach.return_value = session

        run.install_hooks(
            device,
            123,
            resume=lambda **_kwargs: order.append("resume"),
        )

        self.assertEqual(order, ["load", "resume"])

    def test_interactive_mode_marks_script_and_skips_heartbeat_requirement(self):
        callbacks = {}
        script = Mock()
        script.on.side_effect = lambda _event, callback: callbacks.update(
            message=callback
        )
        script.load.side_effect = lambda **_kwargs: callbacks["message"](
            {"payload": {"tag": "appdome-ready"}}, None
        )
        session = Mock(is_detached=False)
        session.create_script.return_value = script
        device = Mock()
        device.attach.return_value = session

        run.install_hooks(device, 123, interactive=True)

        source = session.create_script.call_args.args[0]
        self.assertTrue(
            source.startswith("globalThis.APPDOME_INTERACTIVE = true;")
        )
        stale_health = {
            "heartbeat": time.monotonic() - 60,
            "touches": 0,
            "error": None,
        }
        with patch.object(run, "app_processes", return_value={123: 305}):
            run.require_alive(
                session,
                123,
                stale_health,
                check_heartbeat=False,
            )

    def test_main_cleanup_detaches_only_live_process_before_stopping_server(self):
        for processes, expected in [({123: 305}, ["detach", "cleanup"]),
                                    ({}, ["cleanup"])]:
            with self.subTest(processes=processes), ExitStack() as mocks:
                order = []
                mocks.enter_context(patch("sys.argv", ["run.py", "--interactive"]))
                for name in ["require_installed", "adb", "stop_frida_server",
                             "start_frida_server"]:
                    mocks.enter_context(patch.object(run, name))
                mocks.enter_context(patch.object(run, "detect_device", return_value="emulator-test"))
                mocks.enter_context(patch.object(run, "launch_application", return_value=123))
                mocks.enter_context(patch.object(run, "install_hooks",
                    return_value=(self.session, Mock(), self.health)))
                mocks.enter_context(patch.object(run.time, "sleep", side_effect=KeyboardInterrupt))
                mocks.enter_context(patch.object(run, "app_processes", return_value=processes))
                mocks.enter_context(patch.object(run, "detach_session",
                    side_effect=lambda _: order.append("detach")))
                mocks.enter_context(patch.object(run, "cleanup",
                    side_effect=lambda: order.append("cleanup")))
                run.main()
                self.assertEqual(order, expected)

    def test_server_readiness_retries_rpc_even_when_device_exists(self):
        device = Mock()
        device.enumerate_processes.side_effect = [run.frida.ServerNotRunningError("starting"), []]
        with patch.object(run, "adb_root"), \
                patch.object(run.frida, "get_device", return_value=device), \
                patch.object(run.time, "sleep"):
            self.assertIs(run.start_frida_server(), device)
        self.assertEqual(device.enumerate_processes.call_count, 2)

    def test_cleanup_continues_after_adb_timeout(self):
        with patch.object(run.subprocess, "run", side_effect=[
            run.subprocess.TimeoutExpired("adb", 5), None
        ]) as command:
            run.cleanup()
        self.assertEqual(command.call_count, 2)


if __name__ == "__main__":
    unittest.main()
