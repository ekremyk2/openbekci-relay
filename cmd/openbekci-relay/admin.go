package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/openbekci/openbekci-relay/internal/config"
	"github.com/openbekci/openbekci-relay/internal/store"
)

// admin runs the operator subcommands directly against the SQLite file named
// by RELAY_DB_PATH; the kill switch therefore works even when the HTTP
// service is wedged, and takes effect on the next request (authentication
// reads the server row every time).
func admin(args []string, out io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: admin servers|invites <command> (see --help)")
	}
	cfg, err := config.LoadAdmin()
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DBPath, nil)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	switch args[0] + " " + args[1] {
	case "servers create":
		return serversCreate(ctx, st, cfg, args[2:], out)
	case "servers list":
		return serversList(ctx, st, out)
	case "servers disable":
		return setStatus(ctx, st, args[2:], store.StatusDisabled, out)
	case "servers enable":
		return setStatus(ctx, st, args[2:], store.StatusActive, out)
	case "servers revoke":
		return setStatus(ctx, st, args[2:], store.StatusRevoked, out)
	case "invites create":
		return invitesCreate(ctx, st, args[2:], out)
	case "invites list":
		return invitesList(ctx, st, out)
	case "invites revoke":
		if len(args) != 3 {
			return errors.New("usage: admin invites revoke INVITE_ID")
		}
		if err := st.RevokeInvite(ctx, args[2]); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(out, "revoked", args[2])
		return nil
	}
	return fmt.Errorf("unknown admin command %q %q", args[0], args[1])
}

func serversCreate(ctx context.Context, st *store.Store, cfg config.Config, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("servers create", flag.ContinueOnError)
	appID := fs.String("app-id", "", "app id the server may send for (required)")
	name := fs.String("name", "", "label for operators")
	quota := fs.Int64("daily-quota", -1, "daily message quota (default from config)")
	unverified := fs.Bool("unverified", false, "register as unverified (lower default quota)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *appID == "" {
		return errors.New("--app-id is required")
	}
	q := *quota
	if q < 0 {
		q = cfg.DailyQuota
		if *unverified {
			q = cfg.UnverifiedDailyQuota
		}
	}
	srv, err := st.CreateServer(ctx, store.NewServerParams{Name: *name, AppID: *appID, Verified: !*unverified, DailyQuota: q})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "server_id:     %s\nserver_secret: %s\n\nThe secret is shown once. Put it in the instance's secret file and add to OPENBEKCI_PUSH_RELAYS:\n  <relay_id>=<relay url>;%s;<secret_file>;%s\n", srv.ID, srv.Secret, srv.ID, srv.AppID)
	return nil
}

func serversList(ctx context.Context, st *store.Store, out io.Writer) error {
	list, err := st.ListServers(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SERVER_ID\tSTATUS\tVERIFIED\tAPP_ID\tQUOTA/DAY\tTODAY(accepted/ok/invalid/err/limited)\tNAME\tBASE_URL")
	for _, s := range list {
		c, err := st.Today(ctx, s.ID)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%t\t%s\t%d\t%d/%d/%d/%d/%d\t%s\t%s\n", s.ID, s.Status, s.Verified, s.AppID, s.DailyQuota,
			c.Accepted, c.OK, c.InvalidToken, c.Error, c.RateLimited, s.Name, s.BaseURL)
	}
	return tw.Flush()
}

func setStatus(ctx context.Context, st *store.Store, args []string, status string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: admin servers disable|enable|revoke SERVER_ID")
	}
	if err := st.SetServerStatus(ctx, args[0], status); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("server %s not found (or revoked, which is final)", args[0])
		}
		return err
	}
	_, _ = fmt.Fprintf(out, "%s: %s\n", args[0], status)
	return nil
}

func invitesCreate(ctx context.Context, st *store.Store, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("invites create", flag.ContinueOnError)
	manual := fs.Bool("manual", false, "allow --manual enrollment (no challenge fetch; server flagged unverified)")
	ttl := fs.Duration("ttl", 7*24*time.Hour, "how long the invite stays valid")
	note := fs.String("note", "", "who the invite is for")
	if err := fs.Parse(args); err != nil {
		return err
	}
	code, inv, err := st.CreateInvite(ctx, *manual, *note, *ttl)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "invite_id: %s\ninvite_code: %s\nmanual: %t\nexpires: %s\n\nThe code is shown once and works once.\n", inv.ID, code, inv.Manual, inv.ExpiresAt.Format(time.RFC3339))
	return nil
}

func invitesList(ctx context.Context, st *store.Store, out io.Writer) error {
	list, err := st.ListInvites(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "INVITE_ID\tMANUAL\tEXPIRES\tUSED_BY\tNOTE")
	for _, i := range list {
		used := "-"
		if i.UsedAt != nil {
			used = i.UsedBy
		}
		_, _ = fmt.Fprintf(tw, "%s\t%t\t%s\t%s\t%s\n", i.ID, i.Manual, i.ExpiresAt.Format(time.RFC3339), used, i.Note)
	}
	return tw.Flush()
}
