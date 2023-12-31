<script setup lang="ts">
import type { VNodeRef } from '@vue/runtime-core'
import type { AuditType } from 'nocodb-sdk'
import { enumColor, iconMap, ref, timeAgo, useCopy, useExpandedFormStoreOrThrow, useGlobal, useI18n, watch } from '#imports'

const { loadCommentsAndLogs, commentsAndLogs, isCommentsLoading, commentsOnly, saveComment, isYou, comment, updateComment } =
  useExpandedFormStoreOrThrow()

const commentsWrapperEl = ref<HTMLDivElement>()

await loadCommentsAndLogs()

const showBorder = ref(false)

const { copy } = useCopy()

const { t } = useI18n()

const { user } = useGlobal()

const { isUIAllowed } = useUIPermission()

const hasEditPermission = computed(() => isUIAllowed('commentEditable'))

// currently, edit option is disable on purpose
// since the current update wouldn't keep track of the previous values
// need history of edit feature in order to enable it back
const disableEditOption = ref(true)

const editLog = ref<AuditType>()

const isEditing = ref<boolean>(false)

const focusInput: VNodeRef = (el) => (el as HTMLInputElement)?.focus()

function onKeyDown(event: KeyboardEvent) {
  if (event.key === 'Escape') {
    onKeyEsc(event)
  } else if (event.key === 'Enter') {
    onKeyEnter(event)
  }
}

function onKeyEnter(event: KeyboardEvent) {
  event.stopImmediatePropagation()
  event.preventDefault()
  onEditComment()
}

function onKeyEsc(event: KeyboardEvent) {
  event.stopImmediatePropagation()
  event.preventDefault()
  onCancel()
}

async function onEditComment() {
  if (!isEditing.value || !editLog.value) return
  await updateComment(editLog.value.id!, {
    description: editLog.value.description,
  })
  onStopEdit()
}

function onCancel() {
  if (!isEditing.value) return
  editLog.value = undefined
  onStopEdit()
}

function onStopEdit() {
  isEditing.value = false
  editLog.value = undefined
}

onKeyStroke('Enter', (event) => {
  if (isEditing.value) {
    onKeyEnter(event)
  }
})

const _contextMenu = ref(false)

const contextMenu = computed({
  get: () => _contextMenu.value,
  set: (val) => {
    if (hasEditPermission.value) {
      _contextMenu.value = val
    }
  },
})

async function copyComment(val: string) {
  if (!val) return
  try {
    await copy(val)
    message.success(t('msg.success.commentCopied'))
  } catch (e: any) {
    message.error(e.message)
  }
}

function editComment(log: AuditType) {
  editLog.value = log
  isEditing.value = true
}

watch(
  commentsAndLogs,
  () => {
    // todo: replace setTimeout
    setTimeout(() => {
      if (commentsWrapperEl.value) commentsWrapperEl.value.scrollTop = commentsWrapperEl.value?.scrollHeight
    }, 200)
  },
  { immediate: true },
)
</script>

<template>
  <div class="h-full flex flex-col w-full bg-gray-100 p-2">
    <div ref="commentsWrapperEl" class="flex-1 min-h-[100px] overflow-y-auto scrollbar-thin-dull p-2 space-y-2">
      <a-skeleton v-if="isCommentsLoading" type="list-item-avatar-two-line@8" />
      <template v-else-if="commentsAndLogs.length === 0">
        <div class="flex flex-col text-center justify-center h-full">
          <div class="text-center text-3xl text-gray-300">
            <MdiChatProcessingOutline />
          </div>
          <div class="font-bold text-center my-1 text-gray-400">Start a conversation</div>
          <div class="text-gray-400">
            NocoDB allows you to inquire, monitor progress updates, and collaborate with your team members.
          </div>
        </div>
      </template>
      <template v-else>
        <div v-for="(log, idx) of commentsAndLogs" :key="log.id">
          <a-dropdown :trigger="['contextmenu']" :overlay-class-name="`nc-dropdown-comment-context-menu-${idx}`">
            <div class="flex gap-1 text-xs">
              <component
                :is="iconMap.accountCircle"
                class="row-span-2"
                :class="isYou(log.user) ? 'text-pink-600' : 'text-blue-600 '"
              />

              <div class="flex-1">
                <p class="mb-1 caption edited-text text-[10px] text-gray-500">
                  {{ isYou(log.user) ? 'You' : log.user == null ? 'Shared base' : log.user }}
                  {{ log.op_type === 'COMMENT' ? 'commented' : log.op_sub_type === 'INSERT' ? 'created' : 'edited' }}
                </p>

                <div v-if="log.op_type === 'COMMENT'">
                  <a-input
                    v-if="log.id === editLog?.id"
                    :ref="focusInput"
                    v-model:value="editLog.description"
                    @blur="onCancel"
                    @keydown.stop="onKeyDown($event)"
                  />
                  <p
                    v-else
                    class="block caption my-2 nc-chip w-full min-h-20px p-2 rounded"
                    :style="{ backgroundColor: enumColor.light[2] }"
                  >
                    <!--
                      retrieve the comment part from the audit description
                      `The following comment has been created: foo` -> `foo`
                    -->
                    {{ log.description.substring(log.description.indexOf(':') + 1) }}
                  </p>
                </div>

                <p v-else-if="log.details" v-dompurify-html="log.details" class="caption my-3" style="word-break: break-all" />

                <p v-else>{{ log.description }}</p>

                <p class="time text-right text-[10px] mb-0 mt-1 text-gray-500">
                  {{ timeAgo(log.created_at) }}
                </p>
              </div>
            </div>

            <template #overlay>
              <a-menu v-if="log.op_type === 'COMMENT'" @click="contextMenu = false">
                <a-menu-item key="copy-comment" @click="copyComment(log.description)">
                  <div v-e="['a:comment:copy']" class="nc-project-menu-item">
                    {{ t('general.copy') }}
                  </div>
                </a-menu-item>
                <a-menu-item v-if="log.user === user.email && !disableEditOption" key="edit-comment" @click="editComment(log)">
                  <div v-e="['a:comment:edit']" class="nc-project-menu-item">
                    {{ t('general.edit') }}
                  </div>
                </a-menu-item>
              </a-menu>
            </template>
          </a-dropdown>
        </div>
      </template>
    </div>

    <div class="border-1 my-2 w-full" />

    <div class="p-0">
      <div class="flex justify-center">
        <!-- Comments only -->
        <a-checkbox v-model:checked="commentsOnly" v-e="['c:row-expand:comment-only']" @change="loadCommentsAndLogs">
          {{ $t('labels.commentsOnly') }}
          <span class="text-[11px] text-gray-500" />
        </a-checkbox>
      </div>

      <div v-if="hasEditPermission" class="shrink mt-2 flex">
        <a-input
          v-model:value="comment"
          class="!text-xs nc-comment-box"
          ghost
          :class="{ focus: showBorder }"
          @focusin="showBorder = true"
          @focusout="showBorder = false"
          @keyup.enter.prevent="saveComment"
        >
          <template #addonBefore>
            <div class="flex items-center">
              <component :is="iconMap.accountCircle" class="text-lg text-pink-700" small @click="saveComment" />
            </div>
          </template>

          <template #suffix>
            <component :is="iconMap.returnKey" v-if="comment" class="text-sm" small @click="saveComment" />
          </template>
        </a-input>
      </div>
    </div>
  </div>
</template>

<style scoped>
:deep(.red.lighten-4) {
  @apply bg-red-100;
}

:deep(.green.lighten-4) {
  @apply bg-green-100;
}
</style>
