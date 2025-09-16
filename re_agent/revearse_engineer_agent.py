import asyncio

from dataclasses import dataclass
from pathlib import Path

from langgraph.graph import StateGraph

from agent import Agent
from common import StateInfo, Timer, PatchStoreEntry, logger, Artifact, console
from defaultdataclass import defaultdataclass

from patch_analysis import ida_analysis
from patch_analysis.bindiff_analysis import analyze_diff

from bindiff import BinDiff


@defaultdataclass
class ReverseEngineeringContext:
    state_info: StateInfo
    primary_file: PatchStoreEntry
    secondary_file: PatchStoreEntry
    diff: BinDiff


@defaultdataclass
class ReverseEngineeringOutput:
    artifacts: list[Artifact]


class ReverseEngineering(Agent):
    '''
    Agent that can access specific files in the patch_store and analyze them through:
    1. Disassemble and reverse engineering using IDA pro
    2. Export metadata using binexport plugin
    3. Decompile requested function using RVA
    4. Bindiff two binexport files and generate diff file
    5. Using IDAlib as MCP for further analysis (* Future)
    '''

    @dataclass(frozen=True)
    class NODES:
        analyze = "Analyze binaries"
        diff = "Binary diffing"
        decompile = "Decompile artifacts"

    def __init__(self):
        super().__init__()

    def _build(self):
        if self._graph:
            return

        builder = StateGraph(state_schema=ReverseEngineeringContext, output=ReverseEngineeringOutput)

        builder.add_node(self.NODES.analyze, self.analyze)
        builder.add_node(self.NODES.diff, self.diff)
        builder.add_node(self.NODES.decompile, self.decompile)

        builder.set_entry_point(self.NODES.analyze)
        builder.add_edge(self.NODES.analyze, self.NODES.diff)
        builder.add_edge(self.NODES.diff, self.NODES.decompile)
        builder.set_finish_point(self.NODES.decompile)

        self._graph = builder.compile()

    async def analyze(self, context: ReverseEngineeringContext, config):
        context.state_info.node.append(self.NODES.analyze)
        console.info(f'[*] Start static analysis of {context.primary_file.name}')
        with Timer('analyze and export'):
            await ida_analysis.batch_analysis(files=[
                ida_analysis.ExecArgs(target=Path(context.primary_file.path)),
                ida_analysis.ExecArgs(target=Path(context.secondary_file.path)),
            ],
                condition=lambda file: not file.target.with_name(
                    file.target.name + '.BinExport').exists())
        console.info(f'[+] Finish static analysis of {context.primary_file.name}')

    async def diff(self, context: ReverseEngineeringContext):
        context.state_info.node.append(self.NODES.diff)

        with Timer('generate bindiff'):
            logger.info(f'Diffing {context.primary_file.name} from {context.primary_file.kb} '
                        f'against {context.secondary_file.kb}')

            curr_binexport = context.primary_file.path + '.BinExport'
            prev_binexport = context.secondary_file.path + '.BinExport'
            bindiff_path = f'{context.primary_file.path}.{context.secondary_file.kb}.BinDiff'

            console.info(f'[*] Analyze {context.primary_file.name} code block changes')
            diff = await asyncio.to_thread(BinDiff.from_binexport_files, curr_binexport, prev_binexport, bindiff_path)
            if not diff:
                logger.warning(f'Faild to bindiff {context.primary_file.name}')

            return {'diff': diff}

    async def decompile(self, context: ReverseEngineeringContext):
        context.state_info.node.append(self.NODES.decompile)

        if not context.diff:
            logger.warning("No diff available to add to vector store")
            return {"artifacts": []}

        with Timer('analyze diff and decompile'):
            changed = await analyze_diff(context.diff)
            console.info(f'[+] {len(changed)} functions modified in {context.primary_file.name}')

            return {"artifacts": [Artifact(primary_file=context.primary_file,
                                           secondary_file=context.secondary_file,
                                           diff=context.diff,
                                           changed=changed)]}
