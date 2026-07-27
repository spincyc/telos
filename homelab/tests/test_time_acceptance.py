import unittest

from homelab.vm import time_acceptance as acceptance


class TimeAcceptanceTests(unittest.TestCase):
    def test_response_measures_offset_and_delay(self):
        sent = 1_700_000_000.0
        request = acceptance.request_packet(sent)
        response = bytearray(48)
        response[0] = 0x24
        response[1] = 2
        response[24:32] = request[40:48]
        response[32:40] = acceptance.timestamp(sent + 0.06)
        response[40:48] = acceptance.timestamp(sent + 0.07)
        offset, delay, stratum = acceptance.assess_response(
            bytes(response), request, sent, sent + 0.11
        )
        self.assertAlmostEqual(offset, 0.01, places=6)
        self.assertAlmostEqual(delay, 0.10, places=6)
        self.assertEqual(stratum, 2)

    def test_wrong_origin_is_rejected(self):
        request = acceptance.request_packet(1_700_000_000.0)
        response = bytearray(48)
        response[0] = 0x24
        response[1] = 2
        with self.assertRaisesRegex(ValueError, "does not echo"):
            acceptance.assess_response(
                bytes(response), request, 1_700_000_000.0, 1_700_000_000.1
            )

    def test_udp_123_listener_is_detected_on_ipv4_or_ipv6(self):
        self.assertTrue(
            acceptance.has_ntp_listener(
                "UNCONN 0 0 0.0.0.0:123 0.0.0.0:*\n"
            )
        )
        self.assertTrue(
            acceptance.has_ntp_listener(
                "UNCONN 0 0 [::]:123 [::]:*\n"
            )
        )
        self.assertFalse(
            acceptance.has_ntp_listener(
                "UNCONN 0 0 127.0.0.53:53 0.0.0.0:*\n"
            )
        )


if __name__ == "__main__":
    unittest.main()
