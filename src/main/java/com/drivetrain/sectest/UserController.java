package com.drivetrain.sectest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Clean baseline controller. Delegates lookups to the DAO using a
 * parameterized query. Future feature branches will introduce
 * deliberate vulnerabilities against this baseline.
 */
@RestController
@RequestMapping("/users")
public class UserController {

    private final UserDao userDao;

    @Autowired
    public UserController(UserDao userDao) {
        this.userDao = userDao;
    }

    @GetMapping("/search")
    public List<String> search(@RequestParam("name") String name) {
        return userDao.findByName(name);
    }
}
