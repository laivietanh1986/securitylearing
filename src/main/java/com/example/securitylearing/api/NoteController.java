package com.example.securitylearing.api;

import com.example.securitylearing.entity.Note;
import com.example.securitylearing.repository.NoteRepository;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/notes")
@RequiredArgsConstructor
public class NoteController {
  private final NoteRepository noteRepository;
  @GetMapping
  public List<Note> findAll(){
    return noteRepository.findAll();
  }
  @PostMapping
  public Note create(@Valid @RequestBody Note note){
    return noteRepository.save(note);
  }
  @DeleteMapping("/id")
  @PreAuthorize("hasRole('ADMIN')")
  public void delete(@PathVariable Long id){
    noteRepository.deleteById(id);
  }

}
