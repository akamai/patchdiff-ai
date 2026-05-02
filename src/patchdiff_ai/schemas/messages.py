"""Mixin for LangGraph states that need a `messages` channel."""

from typing import Annotated

from langchain_core.messages import BaseMessage
from pydantic import BaseModel, Field

from patchdiff_ai.schemas.reducers import add_messages


class MessagesState(BaseModel):
    messages: Annotated[list[BaseMessage], add_messages] = Field(default_factory=list)
