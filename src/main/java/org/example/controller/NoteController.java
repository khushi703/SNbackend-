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

import java.util.List;
import java.util.Optional;
@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/notes")
public class NoteController {

    @Autowired
    private NoteService noteService;

    @GetMapping
    public List<NoteDTO> getUserNotes(@AuthenticationPrincipal CustomUserDetails userDetails) {
        if (userDetails == null) {
            throw new RuntimeException("User not authenticated");
        }

        // Fetch only notes belonging to the logged-in user
        return noteService.getNotesByOwner(userDetails.getUser())
                .stream()
                .map(NoteDTO::new)
                .toList();
    }



    @GetMapping("/{id}")
    public ResponseEntity<?> getNoteById(@PathVariable Long id) {
        Optional<Note> note = noteService.getNoteById(id);
        return note.map(n -> ResponseEntity.ok(new NoteDTO(n)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }


    @PostMapping("/create")
    public ResponseEntity<?> createNote(@RequestBody Note note,
                                        @AuthenticationPrincipal CustomUserDetails userDetails) {
        if (userDetails == null) {
            return ResponseEntity.status(401).body("User not authenticated");
        }

        try {
            User user = userDetails.getUser();
            note.setOwner(user);

            Note createdNote = noteService.createNote(note);

            // Convert to DTO to avoid LazyInitializationException
            NoteDTO responseDTO = new NoteDTO(createdNote);

            return ResponseEntity.ok(responseDTO);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error creating note: " + e.getMessage());
        }
    }


    @PutMapping("/{id}")
    public ResponseEntity<?> updateNote(@PathVariable Long id,
                                        @RequestBody Note updatedNote,
                                        @AuthenticationPrincipal CustomUserDetails userDetails) {
        if (userDetails == null) {
            return ResponseEntity.status(401).body("User not authenticated");
        }

        try {
            Note note = noteService.updateNote(id, updatedNote, userDetails.getUser());
            return ResponseEntity.ok(new NoteDTO(note)); // ✅ Return DTO instead of entity
        } catch (RuntimeException e) {
            return ResponseEntity.status(404).body(e.getMessage());
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteNoteById(@PathVariable Long id,
                                            @AuthenticationPrincipal CustomUserDetails userDetails) {
        if (userDetails == null) {
            return ResponseEntity.status(401).body("User not authenticated");
        }

        try {
            noteService.deleteNoteById(id, userDetails.getUser());
            return ResponseEntity.noContent().build();
        } catch (RuntimeException e) {
            return ResponseEntity.status(404).body(e.getMessage());
        }
    }

}
