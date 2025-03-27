package org.example.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
public class Collaboration {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long collaborationId;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user; // The user being invited to collaborate

    @ManyToOne
    @JoinColumn(name = "note_id")
    private Note note; // The note being shared (optional if folder is present)

    @ManyToOne
    @JoinColumn(name = "folder_id")
    private Folder folder; // The folder being shared (optional if note is present)

    private LocalDateTime invitedAt; // Timestamp when the collaboration was invited
    private boolean accepted; // Whether the collaboration has been accepted

    @Enumerated(EnumType.STRING)
    private CollaborationRole role; // Role of the collaborator (e.g., READ, UPDATE)

    @Enumerated(EnumType.STRING)
    private CollaborationStatus status; // Status of the collaboration (e.g., PENDING, ACCEPTED, REJECTED)

    // Default constructor
    public Collaboration() {
        this.invitedAt = LocalDateTime.now(); // Set the invitation timestamp to the current time
        this.status = CollaborationStatus.PENDING; // Default status is PENDING
    }

    // Parameterized constructor
    public Collaboration(User user, Note note, Folder folder, CollaborationRole role) {
        this.user = user;
        this.note = note;
        this.folder = folder;
        this.role = role;
        this.invitedAt = LocalDateTime.now();
        this.status = CollaborationStatus.PENDING;
    }

    // Enum for collaboration roles
    public enum CollaborationRole {
        READ, // Can only view the note/folder
        UPDATE, // Can view and edit the note/folder
        DELETE // Can view, edit, and delete the note/folder
    }

    // Enum for collaboration status
    public enum CollaborationStatus {
        PENDING, // Collaboration request is pending acceptance
        ACCEPTED, // Collaboration request has been accepted
        REJECTED // Collaboration request has been rejected
    }

    // Getters and Setters

    public Long getCollaborationId() {
        return collaborationId;
    }

    public void setCollaborationId(Long collaborationId) {
        this.collaborationId = collaborationId;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Note getNote() {
        return note;
    }

    public void setNote(Note note) {
        this.note = note;
    }

    public Folder getFolder() {
        return folder;
    }

    public void setFolder(Folder folder) {
        this.folder = folder;
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

    // toString method for debugging
    @Override
    public String toString() {
        return "Collaboration{" +
                "collaborationId=" + collaborationId +
                ", user=" + user +
                ", note=" + note +
                ", folder=" + folder +
                ", invitedAt=" + invitedAt +
                ", accepted=" + accepted +
                ", role=" + role +
                ", status=" + status +
                '}';
    }
}