import sqlite3

DB_PATH = "data/mini_siem.db"


def main():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print("=== LANL Multi-Source Correlation Check ===")

    cursor.execute("""
    SELECT source, COUNT(*)
    FROM events
    GROUP BY source
    ORDER BY source;
    """)

    print("\nEvents by source:")
    for row in cursor.fetchall():
        print(row)

    # Redteam destination systems that also appear in auth destination systems
    cursor.execute("""
    SELECT COUNT(*)
    FROM events r
    JOIN events a
    ON json_extract(r.extra, '$.dst_computer') = json_extract(a.extra, '$.dst_computer')
    WHERE r.source = 'lanl_redteam'
    AND a.source = 'lanl_auth';
    """)
    auth_matches = cursor.fetchone()[0]

    # Redteam destination systems that also appear in process logs
    cursor.execute("""
    SELECT COUNT(*)
    FROM events r
    JOIN events p
    ON json_extract(r.extra, '$.dst_computer') = json_extract(p.extra, '$.computer')
    WHERE r.source = 'lanl_redteam'
    AND p.source = 'lanl_proc';
    """)
    proc_matches = cursor.fetchone()[0]

    # Redteam destination systems that also appear in network flow source/destination fields
    cursor.execute("""
    SELECT COUNT(*)
    FROM events r
    JOIN events f
    ON json_extract(r.extra, '$.dst_computer') = json_extract(f.extra, '$.src_computer')
    OR json_extract(r.extra, '$.dst_computer') = json_extract(f.extra, '$.dst_computer')
    WHERE r.source = 'lanl_redteam'
    AND f.source = 'lanl_flows';
    """)
    flow_matches = cursor.fetchone()[0]

    # Redteam destination systems that also appear in DNS lookups
    cursor.execute("""
    SELECT COUNT(*)
    FROM events r
    JOIN events d
    ON json_extract(r.extra, '$.dst_computer') = json_extract(d.extra, '$.src_computer')
    OR json_extract(r.extra, '$.dst_computer') = json_extract(d.extra, '$.resolved_computer')
    WHERE r.source = 'lanl_redteam'
    AND d.source = 'lanl_dns';
    """)
    dns_matches = cursor.fetchone()[0]

    print("\nRedteam destination overlap:")
    print(f"Auth matches: {auth_matches}")
    print(f"Process matches: {proc_matches}")
    print(f"Flow matches: {flow_matches}")
    print(f"DNS matches: {dns_matches}")

    print("\nSample multi-source overlaps:")

    cursor.execute("""
    SELECT
        json_extract(r.extra, '$.lanl_time') AS redteam_time,
        json_extract(r.extra, '$.user') AS redteam_user,
        json_extract(r.extra, '$.src_computer') AS redteam_src,
        json_extract(r.extra, '$.dst_computer') AS redteam_dst,
        a.event_type AS auth_event,
        a.user AS auth_user,
        json_extract(a.extra, '$.lanl_time') AS auth_time,
        p.event_type AS proc_event,
        json_extract(p.extra, '$.process_name') AS process_name,
        json_extract(p.extra, '$.lanl_time') AS proc_time
    FROM events r
    JOIN events a
    ON json_extract(r.extra, '$.dst_computer') = json_extract(a.extra, '$.dst_computer')
    JOIN events p
    ON json_extract(r.extra, '$.dst_computer') = json_extract(p.extra, '$.computer')
    WHERE r.source = 'lanl_redteam'
    AND a.source = 'lanl_auth'
    AND p.source = 'lanl_proc'
    LIMIT 10;
    """)

    for row in cursor.fetchall():
        print(row)

    conn.close()


if __name__ == "__main__":
    main()