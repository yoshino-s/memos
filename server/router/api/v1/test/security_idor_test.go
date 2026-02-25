package test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	apiv1 "github.com/usememos/memos/proto/gen/api/v1"
)

// TestCreateAttachmentIDOR verifies that a user cannot inject attachments into
// another user's memo via the CreateAttachment endpoint.
//
// Security Issue: CreateAttachment does not check memo ownership when a memo
// reference is provided. This allows any authenticated user to inject attachments
// into any other user's memo by knowing the memo UID.
func TestCreateAttachmentIDOR(t *testing.T) {
	ts := NewTestService(t)
	defer ts.Cleanup()
	ctx := context.Background()

	// Create two users
	user1, err := ts.CreateRegularUser(ctx, "victim")
	require.NoError(t, err)
	user1Ctx := ts.CreateUserContext(ctx, user1.ID)

	user2, err := ts.CreateRegularUser(ctx, "attacker")
	require.NoError(t, err)
	user2Ctx := ts.CreateUserContext(ctx, user2.ID)

	// User1 (victim) creates a public memo
	memo, err := ts.Service.CreateMemo(user1Ctx, &apiv1.CreateMemoRequest{
		Memo: &apiv1.Memo{
			Content:    "Victim's memo",
			Visibility: apiv1.Visibility_PUBLIC,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, memo)

	// User2 (attacker) creates an attachment linked to user1's memo
	// This SHOULD fail with permission denied, but currently succeeds
	_, err = ts.Service.CreateAttachment(user2Ctx, &apiv1.CreateAttachmentRequest{
		Attachment: &apiv1.Attachment{
			Filename: "injected.txt",
			Type:     "text/plain",
			Content:  []byte("injected content"),
			Memo:     &memo.Name,
		},
	})

	// SECURITY: This should return a permission denied error
	// Currently this test FAILS because the attachment is created successfully
	require.Error(t, err, "CreateAttachment should deny linking to another user's memo")
	require.Contains(t, err.Error(), "permission denied",
		"Expected permission denied when attacker tries to inject attachment into victim's memo")
}

// TestSetMemoAttachmentsCrossUserLinking verifies that a user cannot link
// another user's attachment to their own memo via SetMemoAttachments.
//
// Security Issue: SetMemoAttachments checks memo ownership but does NOT check
// attachment ownership. This allows a user to "steal" another user's attachment
// by linking it to their own memo.
func TestSetMemoAttachmentsCrossUserLinking(t *testing.T) {
	ts := NewTestService(t)
	defer ts.Cleanup()
	ctx := context.Background()

	// Create two users
	user1, err := ts.CreateRegularUser(ctx, "user1")
	require.NoError(t, err)
	user1Ctx := ts.CreateUserContext(ctx, user1.ID)

	user2, err := ts.CreateRegularUser(ctx, "user2")
	require.NoError(t, err)
	user2Ctx := ts.CreateUserContext(ctx, user2.ID)

	// User1 creates a memo
	user1Memo, err := ts.Service.CreateMemo(user1Ctx, &apiv1.CreateMemoRequest{
		Memo: &apiv1.Memo{
			Content:    "User1's memo",
			Visibility: apiv1.Visibility_PRIVATE,
		},
	})
	require.NoError(t, err)

	// User1 creates an attachment (unlinked)
	user1Attachment, err := ts.Service.CreateAttachment(user1Ctx, &apiv1.CreateAttachmentRequest{
		Attachment: &apiv1.Attachment{
			Filename: "private-file.txt",
			Type:     "text/plain",
			Content:  []byte("sensitive data"),
		},
	})
	require.NoError(t, err)

	// User2 creates their own memo
	user2Memo, err := ts.Service.CreateMemo(user2Ctx, &apiv1.CreateMemoRequest{
		Memo: &apiv1.Memo{
			Content:    "User2's memo",
			Visibility: apiv1.Visibility_PUBLIC,
		},
	})
	require.NoError(t, err)

	// User2 tries to link User1's attachment to User2's memo
	// This SHOULD fail because User2 doesn't own the attachment
	_, err = ts.Service.SetMemoAttachments(user2Ctx, &apiv1.SetMemoAttachmentsRequest{
		Name: user2Memo.Name,
		Attachments: []*apiv1.Attachment{
			{Name: user1Attachment.Name},
		},
	})

	// SECURITY: This should return a permission denied error
	// Currently this test FAILS because the attachment linking succeeds
	require.Error(t, err, "SetMemoAttachments should deny linking another user's attachment")

	// Verify the attachment is still associated with user1 (not stolen)
	listResp, err := ts.Service.ListMemoAttachments(user1Ctx, &apiv1.ListMemoAttachmentsRequest{
		Name: user1Memo.Name,
	})
	require.NoError(t, err)
	// Attachment should NOT have been moved to user2's memo
	fmt.Printf("User1 memo attachments after attack: %d\n", len(listResp.Attachments))
}
