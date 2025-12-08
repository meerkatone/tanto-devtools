try:
  import tanto
except ModuleNotFoundError:
  import binaryninja
  from os import path
  from sys import path as python_path
  python_path.append(path.abspath(path.join(binaryninja.user_plugin_path(), '../repositories/official/plugins')))
  import tanto

from tanto.tanto_view import TantoView

from binaryninja.enums import BranchType, InstructionTextTokenType
from binaryninja import FlowGraph, FlowGraphNode, DisassemblyTextLine, InstructionTextToken

# Inspired by https://github.com/withzombies/bnil-graph


class InstructionGraph(tanto.slices.Slice):
  def __init__(self, parent: 'tanto.tanto_view.TantoView'):
    self.update_style = tanto.slices.UpdateStyle.ON_NAVIGATE

  def __get_class_tokens__(self, name):
    return [InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "<"),
            InstructionTextToken(InstructionTextTokenType.KeywordToken, "class"),
            InstructionTextToken(InstructionTextTokenType.TextToken, ": "),
            InstructionTextToken(InstructionTextTokenType.TypeNameToken, name),
            InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ">")]

  def traverse(self, expr, flowgraph, parent_node, field_name):
    new_node = FlowGraphNode(flowgraph)
    new_node.lines = [DisassemblyTextLine(expr.tokens, expr.address, expr)]

    # This sucks, would be nice to deprecate .lines now that we have line wrapping...
    # this should effectively only be used by HLIL_WHILE and HLIL_DO_WHILE but no promises
    if hasattr(expr, "lines") and len(lines := list(expr.lines)) > 1:
      tokens = []
      for line in lines:
        for token in line.tokens:
          tokens.append(token)
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "; "))
      new_node.lines = [DisassemblyTextLine(tokens[:-1])]
    if field_name is not None:
      new_node.lines = [DisassemblyTextLine(field_name + [token for line in new_node.lines for token in line.tokens])]

    new_node.lines += ["", DisassemblyTextLine(self.__get_class_tokens__(f"{type(expr).__name__}"))]

    flowgraph.append(new_node)
    if parent_node is not None:
      parent_node.add_outgoing_edge(BranchType.UnconditionalBranch, new_node)

    # Traverse manually
    blacklisted_expr_names = {'true', 'false', 'body', 'cases', 'default'}
    for expr_name, inner_expr, _ in expr.detailed_operands:
      if expr_name in blacklisted_expr_names:
        continue
      if isinstance(inner_expr, tanto.helpers.ILInstruction):
        self.traverse(inner_expr, flowgraph, new_node, [InstructionTextToken(InstructionTextTokenType.OperationToken, "."),
                                                        InstructionTextToken(InstructionTextTokenType.FieldNameToken, expr_name),
                                                        InstructionTextToken(InstructionTextTokenType.TextToken, ": ")])
      elif isinstance(inner_expr, list) and all(isinstance(inner_sub_expr, tanto.helpers.ILInstruction) for inner_sub_expr in inner_expr):
        for i, hidden_sub_expr in enumerate(inner_expr):
          self.traverse(hidden_sub_expr, flowgraph, new_node, [InstructionTextToken(InstructionTextTokenType.OperationToken, "."),
                                                               InstructionTextToken(InstructionTextTokenType.FieldNameToken, expr_name),
                                                               InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "["),
                                                               InstructionTextToken(InstructionTextTokenType.FieldNameToken, f"0x{i:x}", value=i),
                                                               InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, "]"),
                                                               InstructionTextToken(InstructionTextTokenType.TextToken, ": ")])
      else:  # Get the things the traverser doesn't, the .var and .constants, etc that aren't ILInstructions
        hidden_expr_node = FlowGraphNode(flowgraph)
        hidden_expr_node.lines = [
          DisassemblyTextLine([
            InstructionTextToken(InstructionTextTokenType.OperationToken, "."),
            InstructionTextToken(InstructionTextTokenType.FieldNameToken, expr_name),
            InstructionTextToken(InstructionTextTokenType.TextToken, ": ")] + self.__get_class_tokens__(f"{type(inner_expr).__name__}"))
        ]
        flowgraph.append(hidden_expr_node)
        new_node.add_outgoing_edge(BranchType.UnconditionalBranch, hidden_expr_node)

      # Special cased fields we want to render:
      if hasattr(expr, "string") and expr.string is not None:
        special_expr_node = FlowGraphNode(flowgraph)
        special_expr_node.lines = [
          DisassemblyTextLine([
            InstructionTextToken(InstructionTextTokenType.OperationToken, "."),
            InstructionTextToken(InstructionTextTokenType.FieldNameToken, "string"),
            InstructionTextToken(InstructionTextTokenType.TextToken, ": ")] + self.__get_class_tokens__("str"))
        ]
        flowgraph.append(special_expr_node)
        new_node.add_outgoing_edge(BranchType.UnconditionalBranch, special_expr_node)

  def get_flowgraph(self) -> FlowGraph:
    if (expr := tanto.helpers.get_selected_expr()) is not None:
      flowgraph = FlowGraph()
      self.traverse(expr, flowgraph, None, None)
      return flowgraph


TantoView.register_slice_type("Instruction Graph", InstructionGraph)
