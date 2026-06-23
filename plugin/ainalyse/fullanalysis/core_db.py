import os
import sqlite3
import ida_nalt
import threading

class AetherDB:
    def __init__(self):
        input_file = ida_nalt.get_input_file_path()
        if not input_file:
            input_file = os.path.join(os.getcwd(), "unknown")
        
        # Store DB adjacent to the binary sample
        db_path = f"{input_file}_aether_context.db"
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS Functions (
                    ea INTEGER PRIMARY KEY,
                    name TEXT,
                    status TEXT,
                    wave_number INTEGER
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS Summaries (
                    ea INTEGER PRIMARY KEY,
                    summary_text TEXT
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS Meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')
            self.conn.commit()

    def set_meta(self, key, value):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO Meta (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value
            ''', (key, value))
            self.conn.commit()

    def get_meta(self, key, default=None):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('SELECT value FROM Meta WHERE key = ?', (key,))
            row = cursor.fetchone()
            return row[0] if row else default

    def upsert_function(self, ea, name, status, wave_number):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO Functions (ea, name, status, wave_number)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ea) DO UPDATE SET
                    name=excluded.name,
                    status=excluded.status,
                    wave_number=excluded.wave_number
            ''', (ea, name, status, wave_number))
            self.conn.commit()

    def get_function_status(self, ea):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('SELECT status FROM Functions WHERE ea = ?', (ea,))
            row = cursor.fetchone()
            return row[0] if row else None

    def get_function_statuses(self, eas):
        """Fetch statuses for multiple EAs in as few queries as possible."""
        if not eas:
            return {}

        # Deduplicate while preserving order to reduce redundant parameters.
        unique_eas = list(dict.fromkeys(eas))
        statuses = {}

        # SQLite has a parameter limit; chunk to stay under it safely.
        chunk_size = 900
        with self.lock:
            cursor = self.conn.cursor()
            for i in range(0, len(unique_eas), chunk_size):
                chunk = unique_eas[i:i + chunk_size]
                placeholders = ",".join("?" for _ in chunk)
                cursor.execute(
                    f"SELECT ea, status FROM Functions WHERE ea IN ({placeholders})",
                    chunk,
                )
                for row in cursor.fetchall():
                    statuses[row[0]] = row[1]

        return statuses

    def has_existing_data(self):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM Functions')
            row = cursor.fetchone()
            return row[0] > 0

    def save_summary(self, ea, summary_text):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO Summaries (ea, summary_text)
                VALUES (?, ?)
                ON CONFLICT(ea) DO UPDATE SET
                    summary_text=excluded.summary_text
            ''', (ea, summary_text))
            self.conn.commit()

    def get_summary(self, ea):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('SELECT summary_text FROM Summaries WHERE ea = ?', (ea,))
            row = cursor.fetchone()
            return row[0] if row else None

    def reset_stale_pending(self) -> int:
        """
        Reset functions stuck in 'Pending' back to allow retry on resume.

        Returns the number of rows affected. Call this at the start of a
        resume so interrupted functions are re-queued rather than silently
        skipped or left in a phantom state.
        """
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM Functions WHERE status = 'Pending'")
            self.conn.commit()
            return cursor.rowcount

    def clear_all_analysis(self):
        """Clears all records to reset the analysis state completely"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM Functions')
            cursor.execute('DELETE FROM Summaries')
            cursor.execute('DELETE FROM Meta')
            self.conn.commit()

    def close(self):
        with self.lock:
            self.conn.close()