package org.example.dto;

import org.example.entities.Collaboration.CollaborationRole;
import org.example.entities.Collaboration.CollaborationStatus;
import java.time.LocalDateTime;

public class CollaborationDTO {
    private Long collaborationId;
    private Long userId;
    private Long noteId;
    private Long folderId;
    private LocalDateTime invitedAt;
    private boolean accepted;
    private CollaborationRole role;
    private CollaborationStatus status;

    public CollaborationDTO() {
    }

    public CollaborationDTO(Long collaborationId, Long userId, Long noteId, Long folderId,
                            LocalDateTime invitedAt, boolean accepted, CollaborationRole role, CollaborationStatus status) {
        this.collaborationId = collaborationId;
        this.userId = userId;
        this.noteId = noteId;
        this.folderId = folderId;
        this.invitedAt = invitedAt;
        this.accepted = accepted;
        this.role = role;
        this.status = status;
    }

    public Long getCollaborationId() {
        return collaborationId;
    }

    public void setCollaborationId(Long collaborationId) {
        this.collaborationId = collaborationId;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public Long getNoteId() {
        return noteId;
    }

    public void setNoteId(Long noteId) {
        this.noteId = noteId;
    }

    public Long getFolderId() {
        return folderId;
    }

    public void setFolderId(Long folderId) {
        this.folderId = folderId;
    }

    public LocalDateTime getInvitedAt() {
        return invitedAt;
    }

    public void setInvitedAt(LocalDateTime invitedAt) {
        this.invitedAt = invitedAt;
    }

    public boolean isAccepted() {
        return accepted;
    }

    public void setAccepted(boolean accepted) {
        this.accepted = accepted;
    }

    public CollaborationRole getRole() {
        return role;
    }

    public void setRole(CollaborationRole role) {
        this.role = role;
    }

    public CollaborationStatus getStatus() {
        return status;
    }

    public void setStatus(CollaborationStatus status) {
        this.status = status;
    }
}