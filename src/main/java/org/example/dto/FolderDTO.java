package org.example.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.example.entities.Folder;
import org.example.entities.Note;

import java.util.Set;
import java.util.stream.Collectors;

public class FolderDTO {
    private Long id;
    private String fname;
    private Set<NoteDTO> notes;

    // Default constructor for Jackson
    public FolderDTO() {
    }

    // Parameterized constructor
    public FolderDTO(Folder folder) {
        this.id = folder.getId();
        this.fname = folder.getFname();
        this.notes = (folder.getNotes() != null) ? folder.getNotes().stream().map(NoteDTO::new).collect(Collectors.toSet()) : null;
    }

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getFname() { return fname; }
    public void setFname(String fname) { this.fname = fname; }

    public Set<NoteDTO> getNotes() { return notes; }
    public void setNotes(Set<NoteDTO> notes) { this.notes = notes; }
}