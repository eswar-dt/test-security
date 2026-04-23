package com.drivetrain.sectest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Clean baseline DAO. Uses parameterized queries via JdbcTemplate.
 * Future branches will introduce vulnerable variants for scanner testing.
 */
@Repository
public class UserDao {

    private final JdbcTemplate jdbc;

    @Autowired
    public UserDao(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<String> findByName(String name) {
        String sql = "SELECT username FROM users WHERE name = ?";
        return jdbc.queryForList(sql, String.class, name);
    }
}
