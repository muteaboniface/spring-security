package com.boniface.springsecuritypractice.service.mapper;

import com.boniface.springsecuritypractice.domain.User;
import com.boniface.springsecuritypractice.service.dto.UserDTO;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring", uses = {})
public interface UserMapper extends EntityMapper<UserDTO, User> {

    UserDTO toDto(User u);

}
