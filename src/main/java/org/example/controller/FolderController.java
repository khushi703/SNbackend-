package org.example.controller;

import org.example.dto.FolderDTO;
import org.example.entities.User;
import org.example.service.CustomUserDetails;
import org.example.service.FolderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/folders")
public class FolderController {

    @Autowired
    private FolderService folderService;

    @PostMapping("/create")
    public ResponseEntity<FolderDTO> createFolder(@RequestBody FolderDTO folderDTO, @AuthenticationPrincipal CustomUserDetails userDetails) {
        User user = userDetails.getUser();
        FolderDTO createdFolder = folderService.saveFolder(folderDTO, user);
        return ResponseEntity.ok(createdFolder);
    }

    @GetMapping("/")
    public ResponseEntity<List<FolderDTO>> getAllFolders(@AuthenticationPrincipal CustomUserDetails userDetails) {
        User user = userDetails.getUser();
        List<FolderDTO> folders = folderService.getFoldersByUser(user);
        return ResponseEntity.ok(folders);
    }

    @GetMapping("/{folderId}")
    public ResponseEntity<FolderDTO> getFolderById(@PathVariable Long folderId, @AuthenticationPrincipal CustomUserDetails userDetails) {
        User user = userDetails.getUser();
        FolderDTO folder = folderService.getFolderByIdAndUser(folderId, user);
        return ResponseEntity.ok(folder);
    }

    @DeleteMapping("/{folderId}")
    public ResponseEntity<String> deleteFolder(@PathVariable Long folderId, @AuthenticationPrincipal CustomUserDetails userDetails) {
        User user = userDetails.getUser();
        folderService.deleteFolder(folderId, user);
        return ResponseEntity.ok("Folder deleted successfully");
    }
}