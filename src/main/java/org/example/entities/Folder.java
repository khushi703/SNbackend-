package org.example.entities;
import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import jakarta.persistence.Entity;
import java.util.Set;

@Entity
public class Folder {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long Folder_id;
    private String fname;

    @ManyToOne
    @JsonIgnore
    @JoinColumn(name = "User_id")
    private User user;

    @OneToMany(mappedBy = "folder", cascade = CascadeType.ALL)
    @JsonManagedReference  // Use @JsonManagedReference for the "notes" relationship
    private Set<Note> notes;

    // Getters and Setters
    public Long getId() {
        return Folder_id;
    }

    public void setId(Long Folder_id) {
        this.Folder_id = Folder_id;
    }

    public String getFname() {
        return fname;
    }

    public void setFname(String fname) {
        this.fname = fname;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Set<Note> getNotes() {
        return notes;
    }

    public void setNotes(Set<Note> notes) {
        this.notes = notes;
    }
}