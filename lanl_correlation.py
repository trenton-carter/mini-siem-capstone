import sqlite3

DB_PATH = "data/mini_siem.db"


def main():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print("=== LANL Correlation Check ===")

    cursor.execute("""
    SELECT COUNT(*)
    FROM events
    WHERE source = 'lanl_auth';
    """)
    auth_count = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM events
    WHERE source = 'lanl_redteam';
    """)
    redteam_count = cursor.fetchone()[0]

    print(f"LANL auth events: {auth_count}")
    print(f"LANL redteam events: {redteam_count}")

    cursor.execute("""
    SELECT COUNT(*)
    FROM events a
    JOIN events r
    ON json_extract(a.extra, '$.src_computer') = json_extract(r.extra, '$.src_computer')
    WHERE a.source = 'lanl_auth'
    AND r.source = 'lanl_redteam';
    """)
    src_matches = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM events a
    JOIN events r
    ON json_extract(a.extra, '$.dst_computer') = json_extract(r.extra, '$.dst_computer')
    WHERE a.source = 'lanl_auth'
    AND r.source = 'lanl_redteam';
    """)
    dst_matches = cursor.fetchone()[0]

    print(f"Matching source computers: {src_matches}")
    print(f"Matching destination computers: {dst_matches}")

    print("\nSample destination computer matches:")

    cursor.execute("""
    SELECT 
        json_extract(r.extra, '$.lanl_time') AS redteam_time,
        json_extract(r.extra, '$.user') AS redteam_user,
        json_extract(r.extra, '$.src_computer') AS redteam_src,
        json_extract(r.extra, '$.dst_computer') AS redteam_dst,
        a.event_type,
        a.user,
        json_extract(a.extra, '$.src_computer') AS auth_src,
        json_extract(a.extra, '$.dst_computer') AS auth_dst,
        json_extract(a.extra, '$.lanl_time') AS auth_time
    FROM events a
    JOIN events r
    ON json_extract(a.extra, '$.dst_computer') = json_extract(r.extra, '$.dst_computer')
    WHERE a.source = 'lanl_auth'
    AND r.source = 'lanl_redteam'
    LIMIT 10;
    """)

    for row in cursor.fetchall():
        print(row)

    conn.close()


if __name__ == "__main__":
    main()