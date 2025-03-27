package org.example.service;

import org.example.dto.CollaborationDTO;
import org.example.entities.Collaboration;
import org.example.entities.Folder;
import org.example.entities.Note;
import org.example.entities.User;
import org.example.repository.CollaborationRepository;
import org.example.repository.FolderRepository;
import org.example.repository.NoteRepository;
import org.example.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CollaborationService {
    @Autowired
    private CollaborationRepository collaborationRepository;
    @Autowired
    private UserRepository userRepository;  // Ensure UserRepository exists
    @Autowired
    private NoteRepository noteRepository;  // Ensure NoteRepository exists
    @Autowired
    private FolderRepository folderRepository;
    public Collaboration addCollaboration(CollaborationDTO collaborationDTO) {
        Collaboration collaboration = new Collaboration();

        collaboration.setCollaborationId(collaborationDTO.getCollaborationId());
        collaboration.setRole(collaborationDTO.getRole());
        collaboration.setStatus(collaborationDTO.getStatus());
        collaboration.setInvitedAt(collaborationDTO.getInvitedAt());

        User user = userRepository.findById(collaborationDTO.getUserId())
                .orElseThrow(() -> new RuntimeException("User not found"));
        collaboration.setUser(user);

        if (collaborationDTO.getNoteId() != null) {
            Note note = noteRepository.findById(collaborationDTO.getNoteId())
                    .orElseThrow(() -> new RuntimeException("Note not found"));
            collaboration.setNote(note);
        }

        if (collaborationDTO.getFolderId() != null) {
            Folder folder = folderRepository.findById(collaborationDTO.getFolderId())
                    .orElseThrow(() -> new RuntimeException("Folder not found"));
            collaboration.setFolder(folder);
        }

        return collaborationRepository.save(collaboration);
    }


    public List<Collaboration> getCollaboratorsByNote(Long noteId) {
        return collaborationRepository.findByNoteId(noteId);
    }

    public List<Collaboration> getCollaboratorsByFolder(Long folderId) {
        return collaborationRepository.findByFolderId(folderId); // New method for folder collaborations
    }

    public void removeCollaboration(Long collaborationId) {
        collaborationRepository.deleteById(collaborationId);
    }

    public Collaboration acceptCollaboration(Long collaborationId) {
        Collaboration collaboration = collaborationRepository.findById(collaborationId).orElseThrow();
        collaboration.setStatus(Collaboration.CollaborationStatus.ACCEPTED);
        return collaborationRepository.save(collaboration);
    }

    public Collaboration rejectCollaboration(Long collaborationId) {
        Collaboration collaboration = collaborationRepository.findById(collaborationId).orElseThrow();
        collaboration.setStatus(Collaboration.CollaborationStatus.REJECTED);
        return collaborationRepository.save(collaboration);
    }

    public boolean hasFolderPermission(Long userId, Long folderId, Collaboration.CollaborationRole role) {
        List<Collaboration> collaborations = collaborationRepository.findByUserIdAndFolderId(userId, folderId);

        if (collaborations.isEmpty()) {
            System.out.println("❌ No folder collaboration found for user " + userId + " on folder " + folderId);
            return false;
        }

        boolean hasPermission = collaborations.stream()
                .anyMatch(c -> c.getStatus() == Collaboration.CollaborationStatus.ACCEPTED && c.getRole() == role);

        System.out.println("🔍 Checking permission for user " + userId + " on folder " + folderId + ": " + hasPermission);
        return hasPermission;
    }
    public boolean hasNotePermission(Long userId, Long noteId, Collaboration.CollaborationRole role) {
        List<Collaboration> collaborations = collaborationRepository.findByUserIdAndNoteId(userId, noteId);

        if (collaborations.isEmpty()) {
            System.out.println("❌ No collaboration found for user " + userId + " on note " + noteId);
            return false;
        }

        boolean hasPermission = collaborations.stream()
                .anyMatch(c -> c.getStatus() == Collaboration.CollaborationStatus.ACCEPTED && c.getRole() == role);

        System.out.println("🔍 Checking permission for user " + userId + " on note " + noteId + ": " + hasPermission);
        return hasPermission;
    }



}