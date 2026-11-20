import threading

from findings import run_detection
from narrate import narrate_pending
from pending import enrich_pending, find_pending_ips

_lock = threading.Lock()


def run_pipeline():
    if not _lock.acquire(blocking=False):
        print("[pipeline] another run is in progress; skipping")
        return
    try:
        print(f"[pipeline] {len(find_pending_ips())} public IP(s) to check")
        for out in enrich_pending():
            print(f"[pipeline] {out['ip']}: {out['verdict']}")
            for e in out["errors"]:
                print(f"[pipeline]   error: {e}")
        print("[pipeline] detection:", run_detection())
        for item in narrate_pending():
            status = "narrated" if item["ok"] else item.get("error", "not changed")
            print(f"[pipeline] finding #{item['id']}: {status}")
        print("[pipeline] done")
    except Exception as err:
        print(f"[pipeline] failed: {err.__class__.__name__}: {err}")
    finally:
        _lock.release()


if __name__ == "__main__":
    run_pipeline()