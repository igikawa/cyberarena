from typing import Annotated
from unicodedata import category

from pydantic import BaseModel, Field, StringConstraints, field_validator, model_validator

Username = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$")]
Password = Annotated[str, StringConstraints(min_length=10, max_length=128)]
Flag = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]


def validate_flag_value(value: str) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > 256 or any(category(char) == "Cc" for char in normalized):
        raise ValueError("Flag must be 1-256 characters without control characters")
    return normalized


class Credentials(BaseModel):
    username: Username
    password: Password


class AdminPasswordChange(BaseModel):
    current_password: Password
    new_password: Password
    confirm_password: Password

    @model_validator(mode="after")
    def new_passwords_must_match(self) -> "AdminPasswordChange":
        if self.new_password != self.confirm_password:
            raise ValueError("New passwords do not match")
        if self.new_password == self.current_password:
            raise ValueError("New password must differ from the current password")
        return self


class FlagSubmission(BaseModel):
    flag: Flag

    @field_validator("flag")
    @classmethod
    def flag_has_no_control_characters(cls, value: str) -> str:
        return validate_flag_value(value)


class ChallengeInput(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    category: str = Field(min_length=1, max_length=40)
    description: str = Field(min_length=1, max_length=10000)
    points: int = Field(gt=0, le=100000)
    flag: Flag
    is_published: bool = False
    resource_url: str | None = Field(default=None, max_length=500)

    @field_validator("title", "category", "description")
    @classmethod
    def text_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Field must not be blank")
        return value

    @field_validator("flag")
    @classmethod
    def flag_has_no_control_characters(cls, value: str) -> str:
        return validate_flag_value(value)


class ChallengePatch(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=120)
    category: str | None = Field(default=None, min_length=1, max_length=40)
    description: str | None = Field(default=None, min_length=1, max_length=10000)
    points: int | None = Field(default=None, gt=0, le=100000)
    flag: Flag | None = None
    is_published: bool | None = None
    resource_url: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def non_nullable_fields_must_not_be_null(self) -> "ChallengePatch":
        for name in ("title", "category", "description", "points", "is_published"):
            if name in self.model_fields_set and getattr(self, name) is None:
                raise ValueError(f"{name} cannot be null")
        return self

    @field_validator("title", "category", "description")
    @classmethod
    def text_must_not_be_blank(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("Field must not be blank")
        return value

    @field_validator("flag")
    @classmethod
    def flag_has_no_control_characters(cls, value: str | None) -> str | None:
        return validate_flag_value(value) if value is not None else None
