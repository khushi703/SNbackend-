package org.example.service;

import jakarta.transaction.Transactional;
import org.example.dto.FolderDTO;
import org.example.entities.Folder;
import org.example.entities.User;
import org.example.repository.FolderRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class FolderService {

    @Autowired
    private FolderRepository folderRepository;

    @Transactional
    public FolderDTO saveFolder(FolderDTO folderDTO, User user) {
        Folder folder = new Folder();
        folder.setFname(folderDTO.getFname());
        folder.setUser(user);
        Folder savedFolder = folderRepository.save(folder);
        return new FolderDTO(savedFolder);
    }

    @Transactional
    public List<FolderDTO> getFoldersByUser(User user) {
        List<Folder> folders = folderRepository.findByUser(user);
        return folders.stream()
                .map(FolderDTO::new)
                .collect(Collectors.toList());
    }

    @Transactional
    public FolderDTO getFolderByIdAndUser(Long folderId, User user) {
        Folder folder = folderRepository.findByIdAndUser(folderId, user)
                .orElseThrow(() -> new RuntimeException("Folder not found or you are not authorized to access it"));
        return new FolderDTO(folder);
    }

    @Transactional
    public void deleteFolder(Long folderId, User user) {
        Folder folder = folderRepository.findById(folderId)
                .orElseThrow(() -> new RuntimeException("Folder not found"));

        if (!folder.getUser().getId().equals(user.getId())) {
            throw new RuntimeException("You are not authorized to delete this folder");
        }

        folderRepository.delete(folder);
    }
}