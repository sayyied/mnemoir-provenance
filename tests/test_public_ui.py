import http.client
import json
import threading

from mnemoir_provenance.local_ui import CSP, build_server


def test_loopback_ui_security_routes_and_state(seeded_db):
    server = build_server(db_path=seeded_db, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/")
        response = conn.getresponse()
        assert response.status == 200
        assert response.getheader("Content-Security-Policy") == CSP
        html = response.read().decode()
        assert "Mnemoir Provenance" in html
        for view in ("home", "recall", "memory", "council", "system"):
            conn.request("GET", f"/api/view/{view}")
            payload = json.loads(conn.getresponse().read())
            assert payload["status"] in {"ok", "degraded", "unavailable"}
        conn.request("GET", "/api/session")
        token = json.loads(conn.getresponse().read())["mutation_token"]
        body = json.dumps({"title": "UI proposal", "summary": "Synthetic", "body": "UI lifecycle", "evidence_ids": ["demo_evidence"]})
        conn.request("POST", "/api/action/proposal.create", body=body, headers={"Content-Type": "application/json", "Origin": server.origin, "X-MNEMOIR-Mutation-Token": token})
        accepted = conn.getresponse()
        assert accepted.status == 200
        assert json.loads(accepted.read())["result"]["proposal_status"] == "proposed"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
