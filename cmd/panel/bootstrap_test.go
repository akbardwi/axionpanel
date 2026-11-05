package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"axionpanel/internal/auth"
	"axionpanel/internal/store"
)

const bootstrapTestEntrance = "/AbCdEf0123_-"
const bootstrapTestOrigin = "https://panel.example.test"

func newBootstrapTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal("secure private test directory failed")
	}
	db, err := store.Open(filepath.Join(dir, "panel.db"))
	if err != nil {
		t.Fatal("open test database failed")
	}
	t.Cleanup(func() { db.Close() })
	if store.Migrate(context.Background(), db) != nil {
		t.Fatal("migrate test database failed")
	}
	return db, dir
}

func bootstrapTestUserCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM users`).Scan(&count); err != nil {
		t.Fatal("count users failed")
	}
	return count
}

func readBootstrapArtifact(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	var artifact map[string]string
	if err := json.Unmarshal(data, &artifact); err != nil {
		t.Fatalf("decode artifact: %v", err)
	}
	return artifact
}

func requireBootstrapError(t *testing.T, db *sql.DB, username, output, entrance, origin string) error {
	t.Helper()
	err := bootstrapToFile(context.Background(), db, username, output, entrance, origin)
	if err == nil {
		t.Fatal("expected bootstrap failure")
	}
	return err
}

func TestBootstrapToFileCreatesProtectedAdminArtifact(t *testing.T) {
	db, dir := newBootstrapTestDB(t)
	output := filepath.Join(dir, "credentials.json")
	if err := bootstrapToFile(context.Background(), db, "  initial-admin  ", output, bootstrapTestEntrance, bootstrapTestOrigin); err != nil {
		t.Fatal("bootstrap failed")
	}
	info, err := os.Lstat(output)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("artifact must be a regular owner-only file")
	}
	artifact := readBootstrapArtifact(t, output)
	if len(artifact) != 4 || artifact["username"] != "initial-admin" || artifact["entrance_path"] != bootstrapTestEntrance || artifact["origin"] != bootstrapTestOrigin || len(artifact["password"]) != 24 {
		t.Fatal("artifact fields invalid")
	}
	var username, hash, role string
	if err := db.QueryRow(`SELECT username,password_hash,role FROM users`).Scan(&username, &hash, &role); err != nil {
		t.Fatal("read administrator failed")
	}
	if username != artifact["username"] || role != "admin" || !auth.VerifyPassword(hash, artifact["password"]) {
		t.Fatal("stored administrator does not match artifact")
	}
	if count := bootstrapTestUserCount(t, db); count != 1 {
		t.Fatal("expected exactly one administrator")
	}
}

func TestBootstrapToFileRejectsUnsafeInputsAndLeavesNoArtifact(t *testing.T) {
	db, dir := newBootstrapTestDB(t)
	tests := []struct {
		name     string
		username string
		entrance string
		origin   string
	}{
		{name: "empty username", username: "   ", entrance: bootstrapTestEntrance, origin: bootstrapTestOrigin},
		{name: "overlong username", username: strings.Repeat("a", 129), entrance: bootstrapTestEntrance, origin: bootstrapTestOrigin},
		{name: "missing entrance slash", username: "admin", entrance: "AbCdEf0123_", origin: bootstrapTestOrigin},
		{name: "short entrance", username: "admin", entrance: "/AbCdEf0123", origin: bootstrapTestOrigin},
		{name: "long entrance", username: "admin", entrance: "/AbCdEf0123_-AbCdEf", origin: bootstrapTestOrigin},
		{name: "non-base64url entrance", username: "admin", entrance: "/AbC!Ef0123_-", origin: bootstrapTestOrigin},
		{name: "missing origin", username: "admin", entrance: bootstrapTestEntrance, origin: ""},
		{name: "HTTP origin", username: "admin", entrance: bootstrapTestEntrance, origin: "http://localhost:7800"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(dir, tc.name+".json")
			if err := requireBootstrapError(t, db, tc.username, output, tc.entrance, tc.origin); err != nil {
				if strings.Contains(err.Error(), output) {
					t.Fatal("error exposes artifact path")
				}
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatal("failed validation must not create artifact")
			}
			if count := bootstrapTestUserCount(t, db); count != 0 {
				t.Fatal("failed validation must not create administrator")
			}
		})
	}
}

func TestBootstrapToFileExistingAdministratorLeavesNoArtifact(t *testing.T) {
	db, dir := newBootstrapTestDB(t)
	if err := bootstrapToFile(context.Background(), db, "first", filepath.Join(dir, "first.json"), bootstrapTestEntrance, bootstrapTestOrigin); err != nil {
		t.Fatal("first bootstrap failed")
	}
	second := filepath.Join(dir, "second.json")
	if err := requireBootstrapError(t, db, "second", second, bootstrapTestEntrance, bootstrapTestOrigin); err == nil {
		t.Fatal("second bootstrap must fail")
	}
	if _, err := os.Lstat(second); !os.IsNotExist(err) {
		t.Fatal("existing administrator must not create another artifact")
	}
	if count := bootstrapTestUserCount(t, db); count != 1 {
		t.Fatal("existing database must be unchanged")
	}
}

func TestBootstrapToFileRejectsExistingOutputNoClobber(t *testing.T) {
	db, dir := newBootstrapTestDB(t)
	existing := filepath.Join(dir, "existing.json")
	if err := os.WriteFile(existing, []byte("{}"), 0o600); err != nil {
		t.Fatalf("create preexisting file: %v", err)
	}
	original := []byte("{}")
	if err := requireBootstrapError(t, db, "admin", existing, bootstrapTestEntrance, bootstrapTestOrigin); err != nil {
		if strings.Contains(err.Error(), existing) {
			t.Fatal("error must not expose artifact path")
		}
	}
	if data, err := os.ReadFile(existing); err != nil || string(data) != string(original) {
		t.Fatal("preexisting artifact must remain unchanged")
	}
	if count := bootstrapTestUserCount(t, db); count != 0 {
		t.Fatal("unwritable output must not create administrator")
	}
}

func TestBootstrapToFileRejectsSymlinkOutputAndParent(t *testing.T) {
	db, dir := newBootstrapTestDB(t)
	target := filepath.Join(dir, "real.json")
	symlink := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatalf("create symlink output: %v", err)
	}
	if err := requireBootstrapError(t, db, "admin", symlink, bootstrapTestEntrance, bootstrapTestOrigin); err == nil {
		t.Fatal("symlink output must be rejected")
	}
	linkParent := filepath.Join(dir, "link-parent")
	realParent := filepath.Join(dir, "real-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatalf("create real parent: %v", err)
	}
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatalf("create symlink parent: %v", err)
	}
	if err := requireBootstrapError(t, db, "admin", filepath.Join(linkParent, "out.json"), bootstrapTestEntrance, bootstrapTestOrigin); err == nil {
		t.Fatal("symlink parent must be rejected")
	}
	if count := bootstrapTestUserCount(t, db); count != 0 {
		t.Fatal("rejected paths must not create administrator")
	}
}

func TestBootstrapToFileRejectsUnsafeOutputParent(t *testing.T) {
	db, dir := newBootstrapTestDB(t)
	for name, perm := range map[string]os.FileMode{"group-access": 0o750, "world-access": 0o707} {
		t.Run(name, func(t *testing.T) {
			parent := filepath.Join(dir, "parent-"+name)
			if err := os.Mkdir(parent, perm); err != nil {
				t.Fatalf("create parent: %v", err)
			}
			if err := requireBootstrapError(t, db, "admin", filepath.Join(parent, "out.json"), bootstrapTestEntrance, bootstrapTestOrigin); err == nil {
				t.Fatal("unsafe parent must be rejected")
			}
			if count := bootstrapTestUserCount(t, db); count != 0 {
				t.Fatal("rejected parent must not create administrator")
			}
		})
	}
}

func TestBootstrapToFileConcurrentCallsCreateExactlyOneAdministrator(t *testing.T) {
	for _, sameOutput := range []bool{false, true} {
		name := "different-output"
		if sameOutput {
			name = "same-output"
		}
		t.Run(name, func(t *testing.T) {
			db, dir := newBootstrapTestDB(t)
			other, err := store.Open(filepath.Join(dir, "panel.db"))
			if err != nil {
				t.Fatal("open independent database handle failed")
			}
			defer other.Close()
			outputs := []string{filepath.Join(dir, "first.json"), filepath.Join(dir, "second.json")}
			if sameOutput {
				outputs[1] = outputs[0]
			}
			dbs := []*sql.DB{db, other}
			errs := make(chan error, 2)
			start := make(chan struct{})
			for i := range dbs {
				go func(i int) {
					<-start
					errs <- bootstrapToFile(context.Background(), dbs[i], fmt.Sprintf("admin-%d", i), outputs[i], bootstrapTestEntrance, bootstrapTestOrigin)
				}(i)
			}
			close(start)
			successes := 0
			for range dbs {
				if <-errs == nil {
					successes++
				}
			}
			if successes != 1 || bootstrapTestUserCount(t, db) != 1 {
				t.Fatal("concurrent bootstrap must create exactly one administrator")
			}
			artifacts := 0
			for i, output := range outputs {
				if sameOutput && i == 1 {
					continue
				}
				info, err := os.Lstat(output)
				if os.IsNotExist(err) {
					continue
				}
				if err != nil || !info.Mode().IsRegular() {
					t.Fatal("unexpected concurrent artifact state")
				}
				artifacts++
			}
			if artifacts != 1 {
				t.Fatal("exactly one bootstrap artifact required")
			}
		})
	}
}

func TestBootstrapToFileDirectoryOutputRejected(t *testing.T) {
	db, dir := newBootstrapTestDB(t)
	output := filepath.Join(dir, "directory.json")
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatalf("create directory output: %v", err)
	}
	if err := requireBootstrapError(t, db, "admin", output, bootstrapTestEntrance, bootstrapTestOrigin); err == nil {
		t.Fatal("directory output must be rejected")
	}
	if info, err := os.Lstat(output); err != nil || !info.IsDir() {
		t.Fatal("directory output must remain intact")
	}
	if count := bootstrapTestUserCount(t, db); count != 0 {
		t.Fatal("directory output must not create administrator")
	}
}

func TestBootstrapToFileRejectsMissingOutputAndUnwritableParent(t *testing.T) {
	db, dir := newBootstrapTestDB(t)
	requireBootstrapError(t, db, "admin", "", bootstrapTestEntrance, bootstrapTestOrigin)
	parent := filepath.Join(dir, "unwritable")
	if os.Mkdir(parent, 0500) != nil {
		t.Fatal("prepare unwritable parent failed")
	}
	defer os.Chmod(parent, 0700)
	before, err := os.Stat(parent)
	if err != nil {
		t.Fatal("inspect parent failed")
	}
	requireBootstrapError(t, db, "admin", filepath.Join(parent, "out.json"), bootstrapTestEntrance, bootstrapTestOrigin)
	after, err := os.Stat(parent)
	if err != nil || before.Mode() != after.Mode() {
		t.Fatal("input parent permissions changed")
	}
	if bootstrapTestUserCount(t, db) != 0 {
		t.Fatal("failed output must not leave account")
	}
}

func TestBootstrapToFileRejectsEntranceWithNewline(t *testing.T) {
	db, dir := newBootstrapTestDB(t)
	invalid := "/AbCdEf0123\r\n"
	requireBootstrapError(t, db, "admin", filepath.Join(dir, "out.json"), invalid, bootstrapTestOrigin)
	if bootstrapTestUserCount(t, db) != 0 {
		t.Fatal("invalid entrance must not leave account")
	}
}

func TestBootstrapToFileRejectsUnsearchableParent(t *testing.T) {
	db, dir := newBootstrapTestDB(t)
	parent := filepath.Join(dir, "unsearchable")
	if os.Mkdir(parent, 0600) != nil {
		t.Fatal("prepare parent failed")
	}
	defer os.Chmod(parent, 0700)
	requireBootstrapError(t, db, "admin", filepath.Join(parent, "out.json"), bootstrapTestEntrance, bootstrapTestOrigin)
	if bootstrapTestUserCount(t, db) != 0 {
		t.Fatal("unsearchable parent must not leave account")
	}
}

func TestBootstrapToFileRejectsTrailingSlashOutput(t *testing.T) {
	db, dir := newBootstrapTestDB(t)
	if os.Mkdir(filepath.Join(dir, "absent"), 0700) != nil {
		t.Fatal("create output directory failed")
	}
	err := requireBootstrapError(t, db, "admin", filepath.Join(dir, "absent")+string(os.PathSeparator), bootstrapTestEntrance, bootstrapTestOrigin)
	if !strings.Contains(err.Error(), "regular file") {
		t.Fatal("expected directory output rejection")
	}
	if bootstrapTestUserCount(t, db) != 0 {
		t.Fatal("invalid output must not leave account")
	}
}

func TestBootstrapToFileKeepsArtifactAfterCommitError(t *testing.T) {
	db, dir := newBootstrapTestDB(t)
	for _, stmt := range []string{
		`CREATE TABLE bootstrap_parent(id INTEGER PRIMARY KEY)`,
		`CREATE TABLE bootstrap_child(id INTEGER REFERENCES bootstrap_parent(id) DEFERRABLE INITIALLY DEFERRED)`,
		`CREATE TRIGGER bootstrap_commit_failure AFTER INSERT ON users BEGIN INSERT INTO bootstrap_child(id) VALUES(42); END`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal("prepare deferred commit failure failed")
		}
	}
	output := filepath.Join(dir, "recovery.json")
	err := requireBootstrapError(t, db, "admin", output, bootstrapTestEntrance, bootstrapTestOrigin)
	if !strings.Contains(err.Error(), "commit bootstrap transaction") {
		t.Fatal("expected commit-stage failure")
	}
	artifact := readBootstrapArtifact(t, output)
	if len(artifact["password"]) != 24 {
		t.Fatal("commit error must preserve recovery artifact")
	}
}

type bootstrapFailingFile struct {
	stage  string
	closed bool
}

func (f *bootstrapFailingFile) Write(p []byte) (int, error) {
	if f.stage == "write" {
		return 0, fmt.Errorf("sensitive write error")
	}
	if f.stage == "short" {
		return len(p) - 1, nil
	}
	return len(p), nil
}
func (f *bootstrapFailingFile) Sync() error {
	if f.stage == "sync" {
		return fmt.Errorf("sensitive sync error")
	}
	return nil
}
func (f *bootstrapFailingFile) Close() error {
	f.closed = true
	if f.stage == "close" {
		return fmt.Errorf("sensitive close error")
	}
	return nil
}
func TestBootstrapArtifactChecksWriteSyncClose(t *testing.T) {
	for _, stage := range []string{"write", "short", "sync", "close"} {
		t.Run(stage, func(t *testing.T) {
			f := &bootstrapFailingFile{stage: stage}
			err := writeAndCloseBootstrapArtifact(f, []byte("{}"))
			if err == nil || !f.closed {
				t.Fatal("artifact IO failure must close file and fail")
			}
			if strings.Contains(err.Error(), "sensitive") {
				t.Fatal("IO errors must not expose details")
			}
		})
	}
}

func TestBootstrapArtifactCleanupOnlyRemovesOwnedFile(t *testing.T) {
	_, dir := newBootstrapTestDB(t)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal("open private directory failed")
	}
	defer root.Close()
	f, err := root.OpenFile("owned", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("create owned file failed")
	}
	defer f.Close()
	owned, err := f.Stat()
	if err != nil {
		t.Fatal("inspect owned file failed")
	}
	if root.Rename("owned", "original") != nil {
		t.Fatal("move owned file failed")
	}
	if os.WriteFile(filepath.Join(dir, "owned"), []byte("{}"), 0600) != nil {
		t.Fatal("create replacement failed")
	}
	removeOwnedBootstrapArtifact(root, "owned", owned)
	if _, err := root.Lstat("owned"); err != nil {
		t.Fatal("cleanup removed replacement file")
	}
	removeOwnedBootstrapArtifact(root, "original", owned)
	if _, err := root.Lstat("original"); !os.IsNotExist(err) {
		t.Fatal("cleanup retained owned file")
	}
}

func TestBootstrapToFileAllowsOwnerWriteSearchParent(t *testing.T) {
	db, dir := newBootstrapTestDB(t)
	parent := filepath.Join(dir, "private")
	if os.Mkdir(parent, 0300) != nil {
		t.Fatal("create restricted parent failed")
	}
	defer os.Chmod(parent, 0700)
	if bootstrapToFile(context.Background(), db, "admin", filepath.Join(parent, "artifact"), bootstrapTestEntrance, bootstrapTestOrigin) != nil {
		t.Fatal("private writable searchable parent should work")
	}
}

func TestBootstrapToFileRejectsWrongOwnerParent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires chown privilege")
	}
	db, dir := newBootstrapTestDB(t)
	parent := filepath.Join(dir, "wrong-owner")
	if os.Mkdir(parent, 0700) != nil || os.Chown(parent, 65534, 65534) != nil {
		t.Fatal("prepare wrong owner failed")
	}
	requireBootstrapError(t, db, "admin", filepath.Join(parent, "out.json"), bootstrapTestEntrance, bootstrapTestOrigin)
	if bootstrapTestUserCount(t, db) != 0 {
		t.Fatal("wrong owner must not leave account")
	}
}

func TestBootstrapToFileMissingParentRejected(t *testing.T) {
	db, dir := newBootstrapTestDB(t)
	missing := filepath.Join(dir, "missing", "out.json")
	if err := requireBootstrapError(t, db, "admin", missing, bootstrapTestEntrance, bootstrapTestOrigin); err == nil {
		t.Fatal("missing parent must be rejected")
	}
	if count := bootstrapTestUserCount(t, db); count != 0 {
		t.Fatal("missing parent must not create administrator")
	}
}
