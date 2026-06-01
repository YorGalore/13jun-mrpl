from backend.logs.vector_store import insert_log, load_logs, search_logs

__all__ = ["search_logs", "load_logs", "insert_log"]

if __name__ == "__main__":
    print(search_logs("brute force SSH login"))
    print(search_logs("reverse shell connection"))
