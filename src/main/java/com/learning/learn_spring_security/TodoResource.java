package com.learning.learn_spring_security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class TodoResource {

    private final Logger logger = LoggerFactory.getLogger(TodoResource.class);

    public static final List<Todo> TODOS = List.of(new Todo("Suryanshu", "Learn AWS"),
            new Todo("Suryanshu", "Learn Kafka"));

    @GetMapping(path = "/todos")
    public List<Todo> retrieveAllTodos()
    {
        return TODOS;
    }

    @GetMapping(path="/users/{username}/todos")
    public Todo retrieveTodosForSpecificUser(@PathVariable String username){
        return TODOS.get(0);
    }

    @PostMapping(path="/users/{username}/todos")
    public void createTodoForSpecificUser(@PathVariable String username, @RequestBody Todo todo){
        //logger.info("Creating " + todo + " for " + username);
        logger.info("Creating {} for {} ", todo,username);
    }

    // Right now Spring security allows all get request to pass through but not the post requests.
}

record Todo (String username, String description){

}
