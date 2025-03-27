package org.example.dto;
import org.example.entities.Note;
import org.example.entities.Note;
import java.time.LocalDateTime;

public class NoteDTO {
    private Long id;
    private String title;
    private String encryptedContent;
    private LocalDateTime createdDate;
    private LocalDateTime updatedDate;
    private String ownerName;
    private Long folderId;

    // Constructor to map Note entity to DTO
    public NoteDTO(Note note) {
        this.id = note.getId();
        this.title = note.getTitle();
        this.encryptedContent = note.getEncryptedContent();
        this.createdDate = note.getCreatedDate();
        this.updatedDate = note.getUpdatedDate();
        this.ownerName = (note.getOwner() != null) ? note.getOwner().getUsername() : null;
        this.folderId = (note.getFolder() != null) ? note.getFolder().getId() : null;
    }

    // Getters
    public Long getId() { return id; }
    public String getTitle() { return title; }
    public String getEncryptedContent() { return encryptedContent; }
    public LocalDateTime getCreatedDate() { return createdDate; }
    public LocalDateTime getUpdatedDate() { return updatedDate; }
    public String getOwnerName() { return ownerName; }
    public Long getFolderId() { return folderId; }
}
