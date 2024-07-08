package com.dzmitrybeinia.webfluxsecurity.mapper;

import com.dzmitrybeinia.webfluxsecurity.dto.UserDto;
import com.dzmitrybeinia.webfluxsecurity.entity.User;
import org.mapstruct.InheritInverseConfiguration;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {
    UserDto map(User user);

    @InheritInverseConfiguration
    User map(UserDto dto);
}
