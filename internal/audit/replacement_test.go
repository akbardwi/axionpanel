package audit_test

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
)

func TestAuditRejectsReplacementOnPooledConnections(t *testing.T) {
	db := database(t) // Production store.Open DSN, not test-only pragmas.
	ctx := context.Background()
	const poolSize = 4
	db.SetMaxOpenConns(poolSize)
	db.SetMaxIdleConns(0) // Each round must create fresh physical connections.
	for round := 0; round < 2; round++ {
		t.Run(fmt.Sprintf("pool_generation_%d", round), func(t *testing.T) {
			// Hold every connection: database/sql cannot hide an unconfigured
			// connection by repeatedly reusing the one opened during migration.
			var conns []*sql.Conn
			defer func() {
				for _, conn := range conns {
					conn.Close()
				}
			}()
			for i := 0; i < poolSize; i++ {
				conn, err := db.Conn(ctx)
				if err != nil {
					t.Fatal(err)
				}
				conns = append(conns, conn)
				var recursive, foreignKeys int
				if err = conn.QueryRowContext(ctx, `PRAGMA recursive_triggers`).Scan(&recursive); err != nil || recursive != 1 {
					t.Errorf("connection %d recursive_triggers=%d err=%v; replacement protection requires 1", i, recursive, err)
				}
				if err = conn.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil || foreignKeys != 1 {
					t.Errorf("connection %d foreign_keys=%d err=%v", i, foreignKeys, err)
				}
			}
			ids := []int64{-9223372036854775808, -2, -1, 0, 1, 42, 9223372036854775807}
			if round == 0 {
				for _, id := range ids {
					if _, err := conns[0].ExecContext(ctx, `INSERT INTO audit_log(id,action,outcome) VALUES(?,'original','success')`, id); err != nil {
						t.Fatal(err)
					}
				}
			}
			for i, conn := range conns {
				for _, id := range ids {
					for _, alias := range []string{"id", "rowid", "oid", "_rowid_"} {
						for _, prefix := range []string{"REPLACE", "INSERT OR REPLACE"} {
							stmt := prefix + ` INTO audit_log(` + alias + `,action,outcome) VALUES(?,'forged','failure')`
							if _, err := conn.ExecContext(ctx, stmt, id); err == nil {
								t.Errorf("connection %d %s via %s overwrote audit id=%d", i, prefix, alias, id)
							} else if !strings.Contains(err.Error(), "audit_log is append-only") {
								t.Errorf("connection %d %s via %s id=%d wrong rejection: %v", i, prefix, alias, id, err)
							}
							var action, outcome string
							if err := conn.QueryRowContext(ctx, `SELECT action,outcome FROM audit_log WHERE id=?`, id).Scan(&action, &outcome); err != nil || action != "original" || outcome != "success" {
								t.Fatalf("existing event id=%d changed: action=%q outcome=%q err=%v", id, action, outcome, err)
							}
						}
					}
				}
				var n int
				if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM audit_log`).Scan(&n); err != nil || n != len(ids) {
					t.Fatalf("history count=%d want=%d err=%v", n, len(ids), err)
				}
			}
		})
	}
}
