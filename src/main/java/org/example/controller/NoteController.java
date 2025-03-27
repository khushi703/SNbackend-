package org.example.controller;

import org.example.dto.NoteDTO;
import org.example.entities.Note;
import org.example.entities.User;
import org.example.service.CustomUserDetails;
import org.example.service.NoteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/notes")
public class NoteController {

    private static final Logger log = LoggerFactory.getLogger(NoteController.class);

    @Autowired
    private NoteService noteService;

    @GetMapping
    public List<NoteDTO> getUserNotes(@AuthenticationPrincipal CustomUserDetails userDetails) {
        log.debug("GET /api/notes - Fetching notes for authenticated user.");

        if (userDetails == null) {
            log.error("User not authenticated. Access denied.");
            throw new RuntimeException("User not authenticated");
        }

        log.info("Authenticated user: {}", userDetails.getUsername());

        // Fetch only notes belonging to the logged-in user
        List<NoteDTO> notes = noteService.getNotesByOwner(userDetails.getUser())
                .stream()
                .map(NoteDTO::new)
                .toList();

        log.debug("Fetched {} notes for user: {}", notes.size(), userDetails.getUsername());
        return notes;
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getNoteById(@PathVariable Long id) {
        log.debug("GET /api/notes/{} - Fetching note by ID.", id);

        Optional<Note> note = noteService.getNoteById(id);

        if (note.isPresent()) {
            log.info("Note found with ID: {}", id);
            return ResponseEntity.ok(new NoteDTO(note.get()));
        } else {
            log.warn("Note not found with ID: {}", id);
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("/create")
    public ResponseEntity<?> createNote(@RequestBody Note note,
                                        @AuthenticationPrincipal CustomUserDetails userDetails) {
        log.debug("POST /api/notes/create - Creating a new note.");

        if (userDetails == null) {
            log.warn("Unauthorized access attempt to create a note.");
            return ResponseEntity.status(401).body("User not authenticated");
        }

        try {
            User user = userDetails.getUser();
            note.setOwner(user);

            Note createdNote = noteService.createNote(note);

            // Convert to DTO to avoid LazyInitializationException
            NoteDTO responseDTO = new NoteDTO(createdNote);

            log.info("Note created successfully by user: {} with ID: {}", userDetails.getUsername(), createdNote.getId());
            return ResponseEntity.ok(responseDTO);
        } catch (Exception e) {
            log.error("Error creating note: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body("Error creating note: " + e.getMessage());
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> updateNote(@PathVariable Long id,
                                        @RequestBody Note updatedNote,
                                        @AuthenticationPrincipal CustomUserDetails userDetails) {
        log.debug("PUT /api/notes/{} - Updating note with ID: {}", id, id);

        if (userDetails == null) {
            log.warn("Unauthorized access attempt to update note.");
            return ResponseEntity.status(401).body("User not authenticated");
        }

        try {
            log.debug("Validating ownership of note ID: {} by user: {}", id, userDetails.getUsername());
            Note note = noteService.updateNote(id, updatedNote, userDetails.getUser());

            log.info("Note updated successfully with ID: {}", id);
            return ResponseEntity.ok(new NoteDTO(note));
        } catch (RuntimeException e) {
            log.warn("Error updating note with ID: {}, Error: {}", id, e.getMessage());
            return ResponseEntity.status(404).body(e.getMessage());
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteNoteById(@PathVariable Long id,
                                            @AuthenticationPrincipal CustomUserDetails userDetails) {
        log.debug("DELETE /api/notes/{} - Deleting note with ID: {}", id, id);

        if (userDetails == null) {
            log.warn("Unauthorized access attempt to delete note.");
            return ResponseEntity.status(401).body("User not authenticated");
        }

        try {
            log.debug("Checking if user: {} owns note with ID: {}", userDetails.getUsername(), id);
            noteService.deleteNoteById(id, userDetails.getUser());

            log.info("Note deleted successfully with ID: {}", id);
            return ResponseEntity.noContent().build();
        } catch (RuntimeException e) {
            log.warn("Error deleting note with ID: {}, Error: {}", id, e.getMessage());
            return ResponseEntity.status(404).body(e.getMessage());
        }
    }
}
