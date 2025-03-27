package org.example.service;
import org.hibernate.Hibernate;
import org.springframework.transaction.annotation.Transactional;
import org.example.entities.Note;
import org.example.entities.User;
import org.example.entities.Folder;
import org.example.repository.NoteRepository;
import org.example.utils.EncryptionUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class NoteService {

    @Autowired
    private NoteRepository noteRepository;

    @Autowired
    private EncryptionUtil encryptionUtil; // Inject EncryptionUtil
    @Transactional(readOnly = true)
    public List<Note> getAllNotes() {
        return noteRepository.findAll();
    }

    @Transactional(readOnly = true)
    public Optional<Note> getNoteById(Long id) {
        return noteRepository.findById(id)
                .map(note -> {
                    Hibernate.initialize(note.getCollaborations());  // Force load
                    return note;
                });
    }


    public List<Note> getNotesByOwner(User owner) {
        return noteRepository.findByOwner(owner);
    }

    public List<Note> getNotesByFolder(Folder folder) {
        return noteRepository.findByFolder(folder);
    }


    public Note createNote(Note note) {
        try {
            // Encrypt the content
            if (note.getEncryptedContent() != null && !note.getEncryptedContent().isEmpty()) {
                String encryptedContent = encryptionUtil.encrypt(note.getEncryptedContent());
                note.setEncryptedContent(encryptedContent);
            }

            // Hash the password if it's provided
            if (note.getPassword() != null && !note.getPassword().isEmpty()) {
                String hashedPassword = encryptionUtil.encrypt(note.getPassword());
                note.setPassword(hashedPassword);
            }

            // Set timestamps
            note.setCreatedDate(LocalDateTime.now());
            note.setUpdatedDate(LocalDateTime.now());

            // Save the note
            return noteRepository.save(note);
        } catch (Exception e) {
            throw new RuntimeException("Failed to save the note: " + e.getMessage(), e);
        }
    }

    public Note updateNote(Long id, Note updatedNote, User loggedInUser) {
        return noteRepository.findById(id).map(note -> {
            // ✅ Ensure only the owner can update the note
            if (!note.getOwner().getId().equals(loggedInUser.getId())) {
                throw new RuntimeException("You do not have permission to update this note");
            }

            try {
                // ✅ Encrypt content before updating
                if (updatedNote.getEncryptedContent() != null) {
                    String encryptedContent = encryptionUtil.encrypt(updatedNote.getEncryptedContent());
                    note.setEncryptedContent(encryptedContent);
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to encrypt note content", e);
            }

            // ✅ Update other fields if provided
            if (updatedNote.getTitle() != null) {
                note.setTitle(updatedNote.getTitle());
            }
            if (updatedNote.getPassword() != null) {
                note.setPassword(updatedNote.getPassword());
            }

            note.setUpdatedDate(LocalDateTime.now());

            return noteRepository.save(note);
        }).orElseThrow(() -> new RuntimeException("Note not found"));
    }

    public void deleteNoteById(Long id, User loggedInUser) {
        Note note = noteRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Note not found"));

        // ✅ Ensure only the owner can delete the note
        if (!note.getOwner().getId().equals(loggedInUser.getId())) {
            throw new RuntimeException("You do not have permission to delete this note");
        }

        noteRepository.delete(note);
    }

}
